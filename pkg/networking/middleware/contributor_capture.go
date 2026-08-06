package middleware

import (
	"bytes"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// maxCaptureBodyBytes bounds bodies read for contributor capture parsing.
const maxCaptureBodyBytes = 64 << 10 // 64 KiB

// ContributorCaptureMiddleware inspects product API requests and responses and records
// billing entities on the active command capture session when contributor billing is enabled.
type ContributorCaptureMiddleware struct {
	next          http.RoundTripper
	config        configuration.Configuration
	logger        *zerolog.Logger
	activeCommand func() string
}

// NewContributorCaptureMiddleware wraps roundTripper with contributor capture logic.
func NewContributorCaptureMiddleware(
	roundTripper http.RoundTripper,
	config configuration.Configuration,
	logger *zerolog.Logger,
	activeCommand func() string,
) *ContributorCaptureMiddleware {
	return &ContributorCaptureMiddleware{
		next:          roundTripper,
		config:        config,
		logger:        logger,
		activeCommand: activeCommand,
	}
}

func (m *ContributorCaptureMiddleware) activeCommandName() string {
	if m.activeCommand == nil {
		return ""
	}
	return m.activeCommand()
}

func (m *ContributorCaptureMiddleware) captureEnabledForBillableHTTP() bool {
	return capture.CaptureEnabledForBillableHTTP(m.config, m.activeCommandName())
}

func (m *ContributorCaptureMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.config == nil || req == nil || req.URL == nil {
		return m.next.RoundTrip(req)
	}

	// Resolve capture config only for product API traffic we might capture. Reading the
	// capture flag on org/FFS/auth requests can recurse (flag default → org lookup → HTTP → middleware).
	_, _, matched := m.matchedCaptureRequest(req)
	if !matched {
		return m.next.RoundTrip(req)
	}

	if !m.config.GetBool(capture.ConfigurationKeyCaptureEnabled) {
		return m.next.RoundTrip(req)
	}

	if m.captureEnabledForBillableHTTP() {
		capture.EnsureCaptureSessionForConfig(m.config, m.activeCommandName())
	}

	bag := capture.ActiveCapture()
	var createTestMeta capture.CreateTestRequestMeta
	var hasCreateTestMeta bool
	if bag != nil && m.captureEnabledForBillableHTTP() {
		createTestMeta, hasCreateTestMeta = m.readCreateTestMeta(req)
	}

	res, err := m.next.RoundTrip(req)
	if err != nil || res == nil {
		return res, err
	}

	if bag != nil && m.captureEnabledForBillableHTTP() {
		m.tryCapture(req, res, bag, hasCreateTestMeta, createTestMeta)
	}
	return res, err
}

func (m *ContributorCaptureMiddleware) readCreateTestMeta(req *http.Request) (capture.CreateTestRequestMeta, bool) {
	if req == nil || req.URL == nil {
		return capture.CreateTestRequestMeta{}, false
	}

	endpoint, _, matched := capture.MatchRequest(req.Method, req.URL.Path)
	if !matched || endpoint != capture.EndpointTestCreate {
		return capture.CreateTestRequestMeta{}, false
	}

	bodyBytes, readErr := readRequestBody(req, maxCaptureBodyBytes)
	if readErr != nil && m.logger != nil {
		m.logger.Debug().Err(readErr).Str("path", req.URL.Path).Msg("contributor capture: failed to read request body")
		return capture.CreateTestRequestMeta{}, false
	}

	return capture.ParseCreateTestRequest(bodyBytes)
}

func (m *ContributorCaptureMiddleware) tryCapture(
	req *http.Request,
	res *http.Response,
	bag *capture.Capture,
	hasCreateTestMeta bool,
	createTestMeta capture.CreateTestRequestMeta,
) {
	defer func() {
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
	}()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return
	}

	endpoint, legacyCapability, matched := m.matchedCaptureRequest(req)
	if !matched {
		return
	}

	bodyBytes, parseable, readErr := readResponseBody(res, maxCaptureBodyBytes)
	if readErr != nil {
		if m.logger != nil {
			m.logger.Debug().Err(readErr).Str("path", req.URL.Path).Msg("contributor capture: failed to read response body")
		}
		return
	}
	if !parseable {
		if m.logger != nil {
			m.logger.Debug().
				Int("body_bytes", len(bodyBytes)).
				Str("path", req.URL.Path).
				Msg("contributor capture: skipping parse for oversized response body")
		}
		return
	}

	switch endpoint {
	case capture.EndpointTestCreate:
		m.captureCreateTest(bag, bodyBytes, hasCreateTestMeta, createTestMeta)
	case capture.EndpointTestGet, capture.EndpointTestComponents:
		m.captureTestFollowUp(bag, req, endpoint, bodyBytes)
	default:
		m.captureLegacyRecords(bag, endpoint, req.URL.Path, bodyBytes, legacyCapability)
	}
}

func (m *ContributorCaptureMiddleware) captureCreateTest(
	bag *capture.Capture,
	bodyBytes []byte,
	hasCreateTestMeta bool,
	createTestMeta capture.CreateTestRequestMeta,
) {
	if !hasCreateTestMeta || !createTestMeta.PublishReport {
		return
	}
	testID := capture.ParseCreateTestResponse(bodyBytes)
	if testID == "" {
		return
	}
	bag.RegisterBillableTest(testID, createTestMeta.Capability)
}

func (m *ContributorCaptureMiddleware) captureTestFollowUp(
	bag *capture.Capture,
	req *http.Request,
	endpoint capture.EndpointKind,
	bodyBytes []byte,
) {
	testCapability := m.testCapabilityForPath(bag, req.URL.Path, endpoint)
	if testCapability == "" {
		return
	}
	for _, record := range capture.ParseCaptureRecords(endpoint, req.URL.Path, bodyBytes, testCapability) {
		bag.Add(record)
	}
}

func (m *ContributorCaptureMiddleware) captureLegacyRecords(
	bag *capture.Capture,
	endpoint capture.EndpointKind,
	path string,
	bodyBytes []byte,
	legacyCapability capture.Capability,
) {
	for _, record := range capture.ParseCaptureRecords(endpoint, path, bodyBytes, legacyCapability) {
		bag.Add(record)
	}
}

func (m *ContributorCaptureMiddleware) testCapabilityForPath(bag *capture.Capture, path string, endpoint capture.EndpointKind) capture.Capability {
	var testID string
	switch endpoint {
	case capture.EndpointTestGet:
		testID = capture.TestIDFromGetPath(path)
	case capture.EndpointTestComponents:
		testID = capture.TestIDFromComponentsPath(path)
	case capture.EndpointNone, capture.EndpointRegistryMonitor, capture.EndpointRegistryIaCShare, capture.EndpointTestCreate:
		return ""
	}
	if testID == "" {
		return ""
	}
	capability, ok := bag.BillableTestCapability(testID)
	if !ok {
		return ""
	}
	return capability
}

func (m *ContributorCaptureMiddleware) matchedCaptureRequest(req *http.Request) (capture.EndpointKind, capture.Capability, bool) {
	endpoint, legacyCapability, matched := capture.MatchRequest(req.Method, req.URL.Path)
	if !matched {
		return capture.EndpointNone, "", false
	}

	apiURL := m.config.GetString(configuration.API_URL)
	additionalSubdomains := m.config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	additionalURLs := m.config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)

	isKnownHost, err := ShouldRequireAuthentication(apiURL, req.URL, additionalSubdomains, additionalURLs)
	if !isKnownHost || err != nil {
		return capture.EndpointNone, "", false
	}

	return endpoint, legacyCapability, true
}

func readRequestBody(req *http.Request, maxBytes int64) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	limit := maxBytes + 1
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, limit))
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if int64(len(bodyBytes)) > maxBytes {
		return bodyBytes[:maxBytes], nil
	}
	return bodyBytes, nil
}

func readResponseBody(res *http.Response, maxBytes int64) (bodyBytes []byte, parseable bool, err error) {
	if res.Body == nil {
		return nil, false, nil
	}

	limit := maxBytes + 1
	bodyBytes, err = io.ReadAll(io.LimitReader(res.Body, limit))
	if err != nil {
		if len(bodyBytes) > 0 {
			res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return nil, false, err
	}

	if int64(len(bodyBytes)) <= maxBytes {
		_ = res.Body.Close()
		res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return bodyBytes, true, nil
	}

	original := res.Body
	res.Body = &stitchedReadCloser{
		Reader:     io.MultiReader(bytes.NewReader(bodyBytes), original),
		underlying: original,
	}
	return bodyBytes[:maxBytes], false, nil
}

type stitchedReadCloser struct {
	io.Reader
	underlying io.ReadCloser
}

func (b *stitchedReadCloser) Close() error {
	return b.underlying.Close()
}
