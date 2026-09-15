package contributor_capture

import (
	"net/http"
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	parentmiddleware "github.com/snyk/go-application-framework/pkg/networking/middleware"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

// ContributorCaptureMiddleware inspects product API requests and responses and reports
// captured entity IDs (currently project IDs) to an injected Sink.
type ContributorCaptureMiddleware struct {
	next         http.RoundTripper
	config       configuration.Configuration
	sink         Sink
	logger       *zerolog.Logger
	pendingTests *pendingTests
}

// testState encodes ongoing test's state.
type testState int

const (
	// testUnknown is a test whose creation the middleware never saw.
	testUnknown testState = iota

	// testNotPublishing is a test created without publish_report.
	testNotPublishing

	// testPending is a publishing test where a project ID has not yet been recorded.
	testPending

	// testCaptured is a publishing test whose project ID has been recorded.
	testCaptured
)

type pendingTests struct {
	mu     sync.Mutex
	states map[string]testState
}

// NewContributorCaptureMiddleware returns a middleware that wraps a round tripper
// with contributor capture logic, for registration via NetworkAccess.AddMiddleware.
func NewContributorCaptureMiddleware(
	config configuration.Configuration,
	sink Sink,
	logger *zerolog.Logger,
) networktypes.MiddlewareFunc {
	pt := pendingTests{states: make(map[string]testState)}
	if logger == nil {
		logger = new(zerolog.Nop())
	}
	return func(roundTripper http.RoundTripper) http.RoundTripper {
		return &ContributorCaptureMiddleware{
			next:         roundTripper,
			config:       config,
			sink:         sink,
			logger:       logger,
			pendingTests: &pt,
		}
	}
}

// captureState carries everything gathered from a matched request before it
// is sent, needed to capture entities from its response once it returns.
type captureState struct {
	kind endpointKind

	// publishReport is true when a create test request asks to publish a report.
	publishReport bool

	// publishReportKnown is true if the value of publishReport was read successfully.
	publishReportKnown bool
}

func (m *ContributorCaptureMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return m.next.RoundTrip(req)
	}

	state, needsResponse := m.beginRequestCapture(req)

	if !needsResponse {
		return m.next.RoundTrip(req)
	}

	res, err := m.next.RoundTrip(req)
	if err != nil || res == nil {
		return res, err
	}

	m.completeRequestCapture(state, req, res)
	return res, nil
}

// beginRequestCapture performs whatever capture the request alone allows and
// reports whether the response still has to be processed to finish the job.
func (m *ContributorCaptureMiddleware) beginRequestCapture(req *http.Request) (state captureState, needsResponse bool) {
	defer m.recover()

	kind, matched := m.classifyRequest(req)
	if !matched {
		return captureState{}, false
	}

	state = captureState{kind: kind}

	switch kind {
	case endpointAIBomUpload:
		m.record(contributors.EntityTypeRevision, parseAIBomUploadRevisionID(m.requestBody(req)))
		return state, false
	case endpointTestCreate:
		state.publishReport, state.publishReportKnown = parseCreateTestPublishReport(m.requestBody(req))
	default:
	}

	return state, true
}

// classifyRequest decides whether req is one contributor-capture cares
// about and, if so, what kind it is. Requests to hosts outside the configured
// Snyk API and its authenticated subdomains are never captured.
func (m *ContributorCaptureMiddleware) classifyRequest(req *http.Request) (endpointKind, bool) {
	kind, matched := classifyEndpoint(req.Method, req.URL.Path)
	if !matched {
		return endpointNone, false
	}

	if !m.isKnownHost(req) {
		return endpointNone, false
	}

	return kind, true
}

// isKnownHost reports whether req is addressed to the configured Snyk API. It
// reuses the gate that decides whether to attach credentials, so capture can
// never reach a host the client would not authenticate against.
func (m *ContributorCaptureMiddleware) isKnownHost(req *http.Request) bool {
	apiURL := m.config.GetString(configuration.API_URL)

	known, err := parentmiddleware.ShouldRequireAuthentication(
		apiURL,
		req.URL,
		m.config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS),
		m.config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS),
	)
	if known && err == nil {
		return true
	}

	return false
}

// requestBody peeks req's body for parsing, returning a prefix if needed.
// For request bodies larger than maxCaptureBodyBytes, a truncated prefix is returned
// since parsing (e.g. JSON flag extraction) may work with just the start of the body.
func (m *ContributorCaptureMiddleware) requestBody(req *http.Request) []byte {
	bodyBytes, err := peekRequestBody(req, maxCaptureBodyBytes)
	if err != nil {
		m.sink.RecordMiss(contributors.MissBodyUnreadable)
		return nil
	}
	return bodyBytes
}

// completeRequestCapture extracts and records entities from a matched
// request's response, using the state beginRequestCapture gathered.
func (m *ContributorCaptureMiddleware) completeRequestCapture(state captureState, req *http.Request, res *http.Response) {
	defer m.recover()

	if res.StatusCode >= http.StatusBadRequest {
		m.sink.RecordMiss(contributors.MissErrorStatus)
		return
	}

	parseBytes, ok := m.responseCaptureBytes(res, state.kind)
	if !ok {
		return
	}

	switch state.kind {
	case endpointTestCreate:
		m.recordCreatedTest(parseBytes, state.publishReport, state.publishReportKnown)
		return
	case endpointTestComponents:
		m.captureComponents(req.URL.Path, parseBytes)
		return
	default:
	}

	projectIDs := projectIDsFromResponse(state.kind, parseBytes)
	m.record(contributors.EntityTypeProject, projectIDs...)
}

// responseCaptureBytes returns the part of res's body worth parsing. Bodies need no
// content-encoding handling here: this middleware runs above http.Transport, which
// negotiates and undoes compression before the response reaches us.
func (m *ContributorCaptureMiddleware) responseCaptureBytes(res *http.Response, kind endpointKind) ([]byte, bool) {
	bodyBytes, fullyRead, err := peekResponseBody(res, kind, maxCaptureBodyBytes)
	if err != nil {
		m.sink.RecordMiss(contributors.MissBodyUnreadable)
		return nil, false
	}
	if !fullyRead && !captureAllowsTruncatedBodyParse(kind) {
		m.sink.RecordMiss(contributors.MissBodyTooLarge)
		return nil, false
	}

	return bodyBytes, true
}

func captureAllowsTruncatedBodyParse(kind endpointKind) bool {
	return kind == endpointDeeproxyReport
}

func projectIDsFromResponse(kind endpointKind, parseBytes []byte) []string {
	switch kind {
	case endpointRegistryMonitor:
		return []string{parseMonitorProjectID(parseBytes)}
	case endpointRegistryIaCShare:
		return parseIaCShareProjectIDs(parseBytes)
	case endpointDeeproxyReport:
		return []string{parseDeeproxyReportProjectID(parseBytes)}
	default:
		return nil
	}
}

// captureComponents records the project ID a components response carries, for a
// test that is still waiting to yield one.
func (m *ContributorCaptureMiddleware) captureComponents(path string, parseBytes []byte) {
	testID := testIDFromPath(path)

	switch m.testState(testID) {
	case testNotPublishing, testCaptured:
		return
	case testUnknown:
		m.sink.RecordMiss(contributors.MissNoEntity)
		return
	case testPending:
	}

	projectID := parseComponentsProjectID(parseBytes)
	if projectID == "" {
		m.sink.RecordMiss(contributors.MissNoEntity)
		return
	}

	m.setTestState(testID, testCaptured)
	m.sink.RecordEntity(contributors.EntityTypeProject, projectID)
}

// recordCreatedTest notes what a create-test response means for the components
// polls that follow it.
func (m *ContributorCaptureMiddleware) recordCreatedTest(bodyBytes []byte, publishReport, publishReportKnown bool) {
	if !publishReportKnown {
		m.sink.RecordMiss(contributors.MissBodyUnreadable)
		return
	}

	testID := parseCreateTestID(bodyBytes)
	if testID == "" {
		if publishReport {
			m.sink.RecordMiss(contributors.MissNoEntity)
		}
		return
	}

	if publishReport {
		m.setTestState(testID, testPending)
		return
	}
	m.setTestState(testID, testNotPublishing)
}

func (m *ContributorCaptureMiddleware) setTestState(testID string, state testState) {
	m.pendingTests.mu.Lock()
	defer m.pendingTests.mu.Unlock()
	m.pendingTests.states[testID] = state
}

func (m *ContributorCaptureMiddleware) testState(testID string) testState {
	m.pendingTests.mu.Lock()
	defer m.pendingTests.mu.Unlock()
	return m.pendingTests.states[testID]
}

// record reports each captured ID to the sink.
func (m *ContributorCaptureMiddleware) record(entityType contributors.EntityType, entityIDs ...string) {
	recorded := false
	for _, entityID := range entityIDs {
		if entityID == "" {
			continue
		}
		m.sink.RecordEntity(entityType, entityID)
		recorded = true
	}

	if !recorded {
		m.sink.RecordMiss(contributors.MissNoEntity)
	}
}

func (m *ContributorCaptureMiddleware) recover() {
	if recovered := recover(); recovered != nil {
		m.sink.RecordMiss(contributors.MissPanic)
	}
}
