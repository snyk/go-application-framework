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

	m.startResponseCapture(state, req, res)
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
		revisionID, err := scanRequestBody(req, maxScanBytes, extractAIBomUploadRevisionID)
		m.recordResult(contributors.EntityTypeRevision, revisionID, err)
		return state, false
	case endpointTestCreate:
		report, err := scanRequestBody(req, maxScanBytes, extractCreateTestReport)
		if err != nil {
			m.sink.RecordMiss(missReasonFor(err))
		}
		state.publishReport, state.publishReportKnown = report.report, report.known
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

// startResponseCapture begins extracting the entity a matched request's
// response carries, using the state beginRequestCapture gathered. It returns
// once the body is wrapped; the outcome is recorded by the time it is closed.
func (m *ContributorCaptureMiddleware) startResponseCapture(state captureState, req *http.Request, res *http.Response) {
	defer m.recover()

	if res.StatusCode >= http.StatusBadRequest {
		m.sink.RecordMiss(contributors.MissErrorStatus)
		return
	}

	extract := responseExtractorFor(state.kind)
	if extract == nil {
		return
	}

	switch state.kind {
	case endpointTestCreate:
		if !state.publishReportKnown {
			m.sink.RecordMiss(contributors.MissBodyUnreadable)
			return
		}
		publishReport := state.publishReport
		scanResponseBody(res, maxScanBytes, extract, func(testID string, err error) {
			m.recordCreatedTest(testID, err, publishReport)
		})
	case endpointTestComponents:
		testID := testIDFromPath(req.URL.Path)
		switch m.testState(testID) {
		case testNotPublishing, testCaptured:
			return
		case testUnknown:
			m.sink.RecordMiss(contributors.MissNoEntity)
			return
		case testPending:
		}
		scanResponseBody(res, maxScanBytes, extract, func(projectID string, err error) {
			m.captureComponents(testID, projectID, err)
		})
	default:
		scanResponseBody(res, maxScanBytes, extract, func(projectID string, err error) {
			m.recordResult(contributors.EntityTypeProject, projectID, err)
		})
	}
}

// recordResult reports a scanned entity, or why there was not one.
func (m *ContributorCaptureMiddleware) recordResult(entityType contributors.EntityType, entityID string, err error) {
	defer m.recover()

	if err != nil || entityID == "" {
		m.sink.RecordMiss(missReasonFor(err))
		return
	}

	m.sink.RecordEntity(entityType, entityID)
}

// captureComponents records the project ID a components response carries, for a
// test that is still waiting to yield one.
func (m *ContributorCaptureMiddleware) captureComponents(testID, projectID string, err error) {
	defer m.recover()

	// A poll that landed while this one streamed may have captured it already.
	if m.testState(testID) == testCaptured {
		return
	}

	if err != nil || projectID == "" {
		m.sink.RecordMiss(missReasonFor(err))
		return
	}

	m.setTestState(testID, testCaptured)
	m.sink.RecordEntity(contributors.EntityTypeProject, projectID)
}

// recordCreatedTest notes what a create-test response means for the components
// polls that follow it.
func (m *ContributorCaptureMiddleware) recordCreatedTest(testID string, err error, publishReport bool) {
	defer m.recover()

	if err != nil {
		m.sink.RecordMiss(missReasonFor(err))
		return
	}

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

func (m *ContributorCaptureMiddleware) recover() {
	if recovered := recover(); recovered != nil {
		m.sink.RecordMiss(contributors.MissPanic)
	}
}
