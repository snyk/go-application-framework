package contributor_capture

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// interactionIDHeader carries the CLI's per-command interaction ID on outbound requests.
const interactionIDHeader = "snyk-interaction-id"

// ContributorCaptureMiddleware inspects product API requests and responses and reports
// captured entity IDs (currently project IDs) to an injected Sink.
type ContributorCaptureMiddleware struct {
	next         http.RoundTripper
	config       configuration.Configuration
	sinkProvider SinkProvider
	logger       *zerolog.Logger
}

type pendingTests struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

var pendingTestsSingleton = &pendingTests{ids: make(map[string]struct{})}

// NewContributorCaptureMiddleware wraps roundTripper with contributor capture logic.
func NewContributorCaptureMiddleware(
	roundTripper http.RoundTripper,
	config configuration.Configuration,
	sinkProvider SinkProvider,
	logger *zerolog.Logger,
) *ContributorCaptureMiddleware {
	return &ContributorCaptureMiddleware{
		next:         roundTripper,
		config:       config,
		sinkProvider: sinkProvider,
		logger:       logger,
	}
}

// captureState carries everything gathered from a matched request before it
// is sent, needed to capture entities from its response once it returns.
type captureState struct {
	kind                   EndpointKind
	interactionID          string
	publishReportRequested bool
}

func (m *ContributorCaptureMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.config == nil || req == nil || req.URL == nil {
		return m.next.RoundTrip(req)
	}

	if m.sinkProvider == nil || m.sinkProvider() == nil {
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
	kind, matched := m.classifyRequest(req)
	if !matched {
		return captureState{}, false
	}

	defer m.recover(req)

	state = captureState{
		kind:          kind,
		interactionID: req.Header.Get(interactionIDHeader),
	}

	switch kind {
	case EndpointAIBomUpload:
		m.record(contributors.EntityTypeRevision, state.interactionID, parseAIBomUploadRevisionID(m.requestBody(req)))
		return state, false
	case EndpointTestCreate:
		state.publishReportRequested = parseCreateTestPublishReport(m.requestBody(req))
	default:
	}

	return state, true
}

// classifyRequest decides whether req is one contributor-capture cares
// about and, if so, what kind it is.
func (m *ContributorCaptureMiddleware) classifyRequest(req *http.Request) (EndpointKind, bool) {
	apiURL, err := url.Parse(m.config.GetString(configuration.API_URL))

	if err != nil || req.URL.Hostname() != apiURL.Hostname() {
		return EndpointNone, false
	}

	if req.Header.Get(interactionIDHeader) == "" {
		return EndpointNone, false
	}

	kind, matched := classifyEndpoint(req.Method, req.URL.Path)
	if !matched {
		return EndpointNone, false
	}

	return kind, true
}

// requestBody peeks req's body for parsing, yielding nil if it cannot be read.
// The body stays readable by whoever gets the request next either way.
func (m *ContributorCaptureMiddleware) requestBody(req *http.Request) []byte {
	bodyBytes, err := readRequestBody(req, maxCaptureBodyBytes)
	if err != nil {
		if m.logger != nil {
			m.logger.Debug().Err(err).Str("path", req.URL.Path).Msg("contributor capture: could not read request body")
		}
		return nil
	}
	return bodyBytes
}

// completeRequestCapture extracts and records entities from a matched
// request's response, using the state beginRequestCapture gathered.
func (m *ContributorCaptureMiddleware) completeRequestCapture(state captureState, req *http.Request, res *http.Response) {
	defer m.recover(req)

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return
	}

	bodyBytes, err := readResponseBody(res, maxCaptureBodyBytes)
	if err != nil {
		if m.logger != nil {
			m.logger.Debug().Err(err).Str("path", req.URL.Path).Msg("contributor capture: could not read response body")
		}
		return
	}

	var projectIDs []string
	switch state.kind {
	case EndpointTestCreate:
		m.markTestPending(bodyBytes, state.publishReportRequested)
		return
	case EndpointRegistryMonitor:
		projectIDs = []string{parseMonitorProjectID(bodyBytes)}
	case EndpointRegistryIaCShare:
		// one project per scanned file, so this is the one kind that can yield many
		projectIDs = parseIaCShareProjectIDs(bodyBytes)
	case EndpointTestComponents:
		testID := testIDFromPath(req.URL.Path)
		if testID == "" || !m.isPendingTest(testID) {
			return
		}
		projectID := parseComponentsProjectID(bodyBytes)
		if projectID == "" {
			return // the test is still running; stay pending for the next poll
		}
		m.clearPendingTest(testID)
		projectIDs = []string{projectID}
	default:
	}

	m.record(contributors.EntityTypeProject, state.interactionID, projectIDs...)
}

// markTestPending records that a test ID asked for publish_report.
func (m *ContributorCaptureMiddleware) markTestPending(bodyBytes []byte, publishReportRequested bool) {
	if !publishReportRequested {
		return
	}
	testID := parseCreateTestID(bodyBytes)
	if testID == "" {
		return
	}

	pendingTestsSingleton.mu.Lock()
	pendingTestsSingleton.ids[testID] = struct{}{}
	pendingTestsSingleton.mu.Unlock()
}

// isPendingTest reports whether testID was previously marked pending.
func (m *ContributorCaptureMiddleware) isPendingTest(testID string) bool {
	pendingTestsSingleton.mu.Lock()
	defer pendingTestsSingleton.mu.Unlock()
	_, ok := pendingTestsSingleton.ids[testID]
	return ok
}

// clearPendingTest removes testID once it no longer needs tracking, so
// pendingTests doesn't grow forever with tests that already got captured.
func (m *ContributorCaptureMiddleware) clearPendingTest(testID string) {
	pendingTestsSingleton.mu.Lock()
	delete(pendingTestsSingleton.ids, testID)
	pendingTestsSingleton.mu.Unlock()
}

// record reports each captured ID to the sink. An empty ID means the parser
// found nothing, so callers can hand over whatever they extracted unchecked.
func (m *ContributorCaptureMiddleware) record(entityType contributors.EntityType, interactionID string, entityIDs ...string) {
	sink := m.sinkProvider()
	for _, entityID := range entityIDs {
		if entityID == "" {
			continue
		}
		sink.RecordEntity(entityType, entityID, interactionID)
	}
}

func (m *ContributorCaptureMiddleware) recover(req *http.Request) {
	if recovered := recover(); recovered != nil && m.logger != nil {
		path := ""
		if req != nil && req.URL != nil {
			path = req.URL.Path
		}
		m.logger.Debug().
			Interface("panic", recovered).
			Str("path", path).
			Msg("contributor capture: recovered from panic")
	}
}
