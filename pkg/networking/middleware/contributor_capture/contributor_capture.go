package contributor_capture

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	parentmiddleware "github.com/snyk/go-application-framework/pkg/networking/middleware"
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
	pendingTests *pendingTests
}

type pendingTests struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

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
		pendingTests: &pendingTests{ids: make(map[string]struct{})},
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
	// Interaction ID is required to track and correlate captured entities.
	// Skip capture if it's missing.
	if req.Header.Get(interactionIDHeader) == "" {
		return EndpointNone, false
	}

	kind, matched := classifyEndpoint(req.Method, req.URL.Path)
	if !matched {
		return EndpointNone, false
	}

	if kind == EndpointDeeproxyReport {
		return m.classifyDeeproxyRequest(req)
	}

	apiURL, err := url.Parse(m.config.GetString(configuration.API_URL))
	if err != nil || req.URL.Hostname() != apiURL.Hostname() {
		return EndpointNone, false
	}

	return kind, true
}

func (m *ContributorCaptureMiddleware) classifyDeeproxyRequest(req *http.Request) (EndpointKind, bool) {
	apiURL := m.config.GetString(configuration.API_URL)
	additionalSubdomains := m.config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	additionalURLs := m.config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)

	isKnownHost, err := parentmiddleware.ShouldRequireAuthentication(apiURL, req.URL, additionalSubdomains, additionalURLs)
	if !isKnownHost || err != nil {
		if m.logger != nil {
			m.logger.Debug().
				Str("path", req.URL.Path).
				Str("host", req.URL.Host).
				Str("api_url", apiURL).
				Err(err).
				Bool("known_host", isKnownHost).
				Msg("contributor capture: deeproxy report host not recognized")
		}
		return EndpointNone, false
	}

	return EndpointDeeproxyReport, true
}

// requestBody peeks req's body for parsing, returning a prefix if needed.
// For request bodies larger than maxCaptureBodyBytes, a truncated prefix is returned
// since parsing (e.g. JSON flag extraction) may work with just the start of the body.
// The body stays readable by whoever gets the request next either way.
func (m *ContributorCaptureMiddleware) requestBody(req *http.Request) []byte {
	bodyBytes, err := readRequestBodyForParse(req, maxCaptureBodyBytes)
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

	if state.kind == EndpointTestCreate {
		m.markTestPending(parseBytes, state.publishReportRequested)
		return
	}

	projectIDs := m.projectIDsFromResponse(state.kind, req.URL.Path, parseBytes)
	m.record(contributors.EntityTypeProject, state.interactionID, projectIDs...)
}

func (m *ContributorCaptureMiddleware) responseCaptureBytes(req *http.Request, res *http.Response, kind EndpointKind) ([]byte, bool) {
	bodyBytes, fullyRead, err := readResponseBodyForParse(res, maxCaptureBodyBytes)
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

	parseBytes := bodyBytes
	if encoding := res.Header.Get("Content-Encoding"); encoding != "" {
		decoded, decodeErr := decodeCaptureBody(bodyBytes, encoding)
		if decodeErr != nil {
			if m.logger != nil {
				m.logger.Debug().
					Err(decodeErr).
					Str("path", req.URL.Path).
					Str("content_encoding", encoding).
					Msg("contributor capture: failed to decode response body, using raw bytes")
			}
		} else {
			parseBytes = decoded
		}
	}

	return parseBytes, true
}

func (m *ContributorCaptureMiddleware) projectIDsFromResponse(kind EndpointKind, path string, parseBytes []byte) []string {
	switch kind {
	case EndpointRegistryMonitor:
		return []string{parseMonitorProjectID(parseBytes)}
	case EndpointRegistryIaCShare:
		return parseIaCShareProjectIDs(parseBytes)
	case EndpointTestComponents:
		return m.projectIDsFromComponentsResponse(path, parseBytes)
	case EndpointDeeproxyReport:
		return []string{parseDeeproxyReportProjectID(parseBytes)}
	default:
		return nil
	}
}

func (m *ContributorCaptureMiddleware) projectIDsFromComponentsResponse(path string, parseBytes []byte) []string {
	testID := testIDFromPath(path)
	if testID == "" || !m.isPendingTest(testID) {
		return nil
	}
	projectID := parseComponentsProjectID(parseBytes)
	if projectID == "" {
		return nil
	}
	m.clearPendingTest(testID)
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

// isPendingTest reports whether testID was previously marked pending.
func (m *ContributorCaptureMiddleware) isPendingTest(testID string) bool {
	m.pendingTests.mu.Lock()
	defer m.pendingTests.mu.Unlock()
	_, ok := m.pendingTests.ids[testID]
	return ok
}

// clearPendingTest removes testID once it no longer needs tracking, so
// pendingTests doesn't grow forever with tests that already got captured.
func (m *ContributorCaptureMiddleware) clearPendingTest(testID string) {
	m.pendingTests.mu.Lock()
	delete(m.pendingTests.ids, testID)
	m.pendingTests.mu.Unlock()
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
