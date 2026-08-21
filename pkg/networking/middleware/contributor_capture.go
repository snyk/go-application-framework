package middleware

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"

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
	analyticsCommand := ""
	if m.activeCommand != nil {
		analyticsCommand = m.activeCommand()
	}
	var rawArgs []string
	if m.config != nil {
		rawArgs = m.config.GetStringSlice(configuration.RAW_CMD_ARGS)
	}
	return capture.ResolveBillableCommand(analyticsCommand, rawArgs)
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

	billableCommand := m.activeCommandName()
	if m.captureEnabledForBillableHTTP() {
		capture.EnsureCaptureSessionForConfig(m.config, billableCommand)
	} else if m.logger != nil && strings.HasPrefix(strings.ToLower(req.URL.Path), "/report/") {
		m.logger.Debug().
			Str("path", req.URL.Path).
			Str("command", billableCommand).
			Msg("contributor capture: skipping deeproxy report (command not billable)")
	}

	bag := capture.ActiveCapture()
	var createTestMeta capture.CreateTestRequestMeta
	var hasCreateTestMeta bool
	var aibomUploadRevisionID string
	var hasAIBOMUploadMeta bool
	if bag != nil && m.captureEnabledForBillableHTTP() {
		createTestMeta, hasCreateTestMeta = m.readCreateTestMeta(req)
		aibomUploadRevisionID, hasAIBOMUploadMeta = m.readAIBOMUploadMeta(req)
	}

	res, err := m.next.RoundTrip(req)
	if err != nil || res == nil {
		return res, err
	}

	if bag != nil && m.captureEnabledForBillableHTTP() && !capture.IsSessionSealed() {
		m.tryCapture(req, res, bag, hasCreateTestMeta, createTestMeta, hasAIBOMUploadMeta, aibomUploadRevisionID)
		if bag.HasRecords() {
			capture.SealAndNotifyFirstRecord()
		}
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

func (m *ContributorCaptureMiddleware) readAIBOMUploadMeta(req *http.Request) (revisionID string, ok bool) {
	if req == nil || req.URL == nil {
		return "", false
	}

	endpoint, _, matched := capture.MatchRequest(req.Method, req.URL.Path)
	if !matched || endpoint != capture.EndpointAIBOMUpload {
		return "", false
	}

	bodyBytes, readErr := readRequestBody(req, maxCaptureBodyBytes)
	if readErr != nil && m.logger != nil {
		m.logger.Debug().Err(readErr).Str("path", req.URL.Path).Msg("contributor capture: failed to read AI-BOM upload request body")
		return "", false
	}

	return capture.ParseAIBOMUploadRequest(bodyBytes)
}

func (m *ContributorCaptureMiddleware) tryCapture(
	req *http.Request,
	res *http.Response,
	bag *capture.Capture,
	hasCreateTestMeta bool,
	createTestMeta capture.CreateTestRequestMeta,
	hasAIBOMUploadMeta bool,
	aibomUploadRevisionID string,
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

	endpoint, legacyCapability, matched := m.matchedCaptureRequest(req)
	if !matched {
		return
	}

	if !captureResponseStatusOK(res.StatusCode, endpoint) {
		return
	}

	bodyBytes, parseable, readErr := readResponseBody(res, maxCaptureBodyBytes)
	if readErr != nil {
		if m.logger != nil {
			m.logger.Debug().Err(readErr).Str("path", req.URL.Path).Msg("contributor capture: failed to read response body")
		}
		return
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
	if !parseable && !captureAllowsTruncatedBodyParse(endpoint) {
		if m.logger != nil {
			m.logger.Debug().
				Int("body_bytes", len(bodyBytes)).
				Str("path", req.URL.Path).
				Msg("contributor capture: skipping parse for oversized response body")
		}
		return
	}
	if endpoint == capture.EndpointAIBOMUpload {
		m.captureAIBOMUpload(bag, req.URL.Path, hasAIBOMUploadMeta, aibomUploadRevisionID)
		return
	}
	if len(parseBytes) == 0 {
		return
	}

	switch endpoint {
	case capture.EndpointTestCreate:
		m.captureCreateTest(bag, parseBytes, hasCreateTestMeta, createTestMeta)
	case capture.EndpointTestJobGet:
		m.captureTestJobRedirect(bag, req, parseBytes)
	case capture.EndpointTestGet, capture.EndpointTestComponents:
		m.captureTestFollowUp(bag, req, endpoint, parseBytes)
	default:
		hadRecords := bag.HasRecords()
		m.captureLegacyRecords(bag, endpoint, req.URL.Path, parseBytes, legacyCapability)
		if m.logger != nil && endpoint == capture.EndpointDeeproxyReport && !hadRecords && !bag.HasRecords() {
			m.logger.Debug().
				Str("path", req.URL.Path).
				Int("body_bytes", len(parseBytes)).
				Bool("parseable", parseable).
				Msg("contributor capture: deeproxy report parse produced no records")
		}
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
	jobID := capture.ParseCreateTestResponse(bodyBytes)
	if jobID == "" {
		return
	}
	bag.RegisterBillableTest(jobID, createTestMeta.Capability)
}

func (m *ContributorCaptureMiddleware) captureAIBOMUpload(
	bag *capture.Capture,
	path string,
	hasMeta bool,
	revisionID string,
) {
	if !hasMeta || revisionID == "" {
		return
	}
	record := capture.AIBOMUploadRecord(path, revisionID)
	if record.EntityID == "" {
		return
	}
	bag.Add(record)
}

func (m *ContributorCaptureMiddleware) captureTestJobRedirect(
	bag *capture.Capture,
	req *http.Request,
	bodyBytes []byte,
) {
	if req == nil || req.URL == nil {
		return
	}
	jobID := capture.JobIDFromGetPath(req.URL.Path)
	if jobID == "" {
		return
	}
	testID := capture.ParseTestJobRedirectResponse(bodyBytes)
	if testID == "" {
		return
	}
	bag.PromoteBillableJob(jobID, testID)
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
	case capture.EndpointNone, capture.EndpointRegistryMonitor, capture.EndpointRegistryIaCShare, capture.EndpointTestCreate, capture.EndpointTestJobGet, capture.EndpointDeeproxyReport, capture.EndpointAIBOMUpload:
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
		if m.logger != nil && endpoint == capture.EndpointDeeproxyReport {
			m.logger.Debug().
				Str("path", req.URL.Path).
				Str("host", req.URL.Host).
				Str("api_url", apiURL).
				Err(err).
				Bool("known_host", isKnownHost).
				Msg("contributor capture: deeproxy report host not recognized")
		}
		return capture.EndpointNone, "", false
	}

	return endpoint, legacyCapability, true
}

// captureAllowsTruncatedBodyParse reports whether an endpoint can be parsed from a
// response prefix when the full body exceeds maxCaptureBodyBytes.
func captureResponseStatusOK(statusCode int, endpoint capture.EndpointKind) bool {
	if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
		return true
	}
	return endpoint == capture.EndpointTestJobGet && statusCode == http.StatusSeeOther
}

func captureAllowsTruncatedBodyParse(endpoint capture.EndpointKind) bool {
	switch endpoint {
	case capture.EndpointDeeproxyReport:
		// Legacy Code deeproxy COMPLETE responses embed full SARIF after top-level
		// status/uploadResult fields — the billing entity is in that prefix.
		return true
	default:
		return false
	}
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

func decodeCaptureBody(bodyBytes []byte, contentEncoding string) ([]byte, error) {
	if len(bodyBytes) == 0 {
		return bodyBytes, nil
	}

	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	default:
		return bodyBytes, nil
	}
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
