package contributor_capture

import (
	"net/http"
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributors"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

// ContributorCaptureMiddleware inspects product API requests and responses and reports
// captured entity IDs (currently project IDs) to an injected Sink.
type ContributorCaptureMiddleware struct {
	next         http.RoundTripper
	sink         Sink
	logger       *zerolog.Logger
	pendingTests *pendingTests
}

type pendingTests struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

// NewContributorCaptureMiddleware returns a middleware that wraps a round tripper
// with contributor capture logic, for registration via NetworkAccess.AddMiddleware.
func NewContributorCaptureMiddleware(
	sink Sink,
	logger *zerolog.Logger,
) networktypes.MiddlewareFunc {
	return func(roundTripper http.RoundTripper) http.RoundTripper {
		return &ContributorCaptureMiddleware{
			next:         roundTripper,
			sink:         sink,
			logger:       logger,
			pendingTests: &pendingTests{ids: make(map[string]struct{})},
		}
	}
}

// captureState carries everything gathered from a matched request before it
// is sent, needed to capture entities from its response once it returns.
type captureState struct {
	kind                   endpointKind
	publishReportRequested bool
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
	defer m.recover(req)

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
		state.publishReportRequested = parseCreateTestPublishReport(m.requestBody(req))
	default:
	}

	return state, true
}

// classifyRequest decides whether req is one contributor-capture cares
// about and, if so, what kind it is.
func (m *ContributorCaptureMiddleware) classifyRequest(req *http.Request) (endpointKind, bool) {
	kind, matched := classifyEndpoint(req.Method, req.URL.Path)
	if !matched {
		return endpointNone, false
	}

	return kind, true
}

// requestBody peeks req's body for parsing, returning a prefix if needed.
// For request bodies larger than maxCaptureBodyBytes, a truncated prefix is returned
// since parsing (e.g. JSON flag extraction) may work with just the start of the body.
func (m *ContributorCaptureMiddleware) requestBody(req *http.Request) []byte {
	bodyBytes, err := peekRequestBody(req, maxCaptureBodyBytes)
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

	if res.StatusCode >= http.StatusBadRequest {
		return
	}

	parseBytes, ok := m.responseCaptureBytes(req, res, state.kind)
	if !ok {
		return
	}

	if state.kind == endpointTestCreate {
		m.markTestPending(parseBytes, state.publishReportRequested)
		return
	}

	projectIDs := m.projectIDsFromResponse(state.kind, req.URL.Path, parseBytes)
	m.record(contributors.EntityTypeProject, projectIDs...)
}

// responseCaptureBytes returns the part of res's body worth parsing. Bodies need no
// content-encoding handling here: this middleware runs above http.Transport, which
// negotiates and undoes compression before the response reaches us.
func (m *ContributorCaptureMiddleware) responseCaptureBytes(req *http.Request, res *http.Response, kind endpointKind) ([]byte, bool) {
	bodyBytes, fullyRead, err := peekResponseBody(res, maxCaptureBodyBytes)
	if err != nil {
		if m.logger != nil {
			m.logger.Debug().Err(err).Str("path", req.URL.Path).Msg("contributor capture: could not read response body")
		}
		return nil, false
	}
	if !fullyRead && !captureAllowsTruncatedBodyParse(kind) {
		if m.logger != nil {
			m.logger.Debug().
				Int("body_bytes", len(bodyBytes)).
				Str("path", req.URL.Path).
				Msg("contributor capture: skipping parse for oversized response body")
		}
		return nil, false
	}

	return bodyBytes, true
}

func captureAllowsTruncatedBodyParse(kind endpointKind) bool {
	return kind == endpointDeeproxyReport
}

func (m *ContributorCaptureMiddleware) projectIDsFromResponse(kind endpointKind, path string, parseBytes []byte) []string {
	switch kind {
	case endpointRegistryMonitor:
		return []string{parseMonitorProjectID(parseBytes)}
	case endpointRegistryIaCShare:
		return parseIaCShareProjectIDs(parseBytes)
	case endpointTestComponents:
		return m.projectIDsFromComponentsResponse(path, parseBytes)
	case endpointDeeproxyReport:
		return []string{parseDeeproxyReportProjectID(parseBytes)}
	default:
		return nil
	}
}

func (m *ContributorCaptureMiddleware) projectIDsFromComponentsResponse(path string, parseBytes []byte) []string {
	projectID := parseComponentsProjectID(parseBytes)
	if projectID == "" {
		return nil
	}
	testID := testIDFromPath(path)
	if testID == "" || !m.takeTestIfPending(testID) {
		return nil
	}
	return []string{projectID}
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

	m.pendingTests.mu.Lock()
	m.pendingTests.ids[testID] = struct{}{}
	m.pendingTests.mu.Unlock()
}

// takeTestIfPending reports whether testID was previously marked pending, and
// clears it if the result is true.
func (m *ContributorCaptureMiddleware) takeTestIfPending(testID string) bool {
	m.pendingTests.mu.Lock()
	defer m.pendingTests.mu.Unlock()
	_, ok := m.pendingTests.ids[testID]
	if ok {
		delete(m.pendingTests.ids, testID)
	}
	return ok
}

// record reports each captured ID to the sink. An empty ID means the parser
// found nothing, so callers can hand over whatever they extracted unchecked.
func (m *ContributorCaptureMiddleware) record(entityType contributors.EntityType, entityIDs ...string) {
	for _, entityID := range entityIDs {
		if entityID == "" {
			continue
		}
		m.sink.RecordEntity(entityType, entityID)
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
