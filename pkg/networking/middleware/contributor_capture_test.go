package middleware_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

func captureEnabledConfig(serverURL string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, serverURL)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{serverURL})
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)
	return config
}

func billableMonitorCommand() func() string {
	return func() string { return "monitor" }
}

func newContributorCaptureMiddleware(
	rt http.RoundTripper,
	config configuration.Configuration,
	logger *zerolog.Logger,
	activeCommand ...func() string,
) *middleware.ContributorCaptureMiddleware {
	cmd := billableMonitorCommand()
	if len(activeCommand) > 0 && activeCommand[0] != nil {
		cmd = activeCommand[0]
	}
	return middleware.NewContributorCaptureMiddleware(rt, config, logger, cmd)
}

func openCaptureSession(t *testing.T) *capture.Capture {
	t.Helper()
	capture.ResetCommandSession()
	bag := capture.OpenCommandSession("")
	t.Cleanup(func() { capture.ResetCommandSession() })
	return bag
}

func testJobRedirectBody(testID string) string {
	return `{"data":{"relationships":{"test":{"data":{"id":"` + testID + `"}}}}}`
}

func TestContributorCaptureMiddleware_capturesMonitorProjectID(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/v1/monitor/npm", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			"uri": "https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.NoError(t, res.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, capture.CapabilityOSS, records[0].Capability)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_capturesIaCShareProjectIDs(t *testing.T) {
	const (
		projectIDOne = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		projectIDTwo = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/iac-cli-share-results", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"./main.tf": "` + projectIDOne + `",
			"./other.tf": "` + projectIDTwo + `",
			"ok": true
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/iac-cli-share-results", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NoError(t, res.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 2)
	assert.Equal(t, capture.CapabilityIaC, records[0].Capability)
	assert.Equal(t, capture.CapabilityIaC, records[1].Capability)
	assert.ElementsMatch(t, []string{projectIDOne, projectIDTwo}, []string{records[0].EntityID, records[1].EntityID})
}

func TestContributorCaptureMiddleware_skipsUnknownHost(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	monitorBody := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/v1/monitor/npm", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(monitorBody))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NoError(t, res.Body.Close())

	assert.Empty(t, bag.Snapshot())
}

func TestContributorCaptureMiddleware_skipsNonSuccessResponses(t *testing.T) {
	monitorBody := `{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`

	for _, statusCode := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
				_, err := w.Write([]byte(monitorBody))
				require.NoError(t, err)
			}))
			t.Cleanup(server.Close)

			config := captureEnabledConfig(server.URL)
			bag := openCaptureSession(t)

			logger := zerolog.Nop()
			rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

			req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
			require.NoError(t, err)

			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, statusCode, res.StatusCode)
			require.NoError(t, res.Body.Close())

			assert.Empty(t, bag.Snapshot())
		})
	}
}

func TestContributorCaptureMiddleware_skipsCaptureWhenCommandNotBillable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger, func() string { return "test" })

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)
	require.Nil(t, capture.ActiveCapture())

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())
	assert.Nil(t, capture.ActiveCapture())
}

func TestContributorCaptureMiddleware_lazyOpensSessionForBillableMonitor(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)
	require.Nil(t, capture.ActiveCapture())

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_skipsCaptureWhenFlagDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	assert.Empty(t, bag.Snapshot())
}

func TestContributorCaptureMiddleware_capturesDespiteInflatedContentLength(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	monitorBody := []byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: 70000,
			Body:          io.NopCloser(bytes.NewReader(monitorBody)),
			Request:       req,
		}, nil
	})
	rt := newContributorCaptureMiddleware(next, config, &logger)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_preservesOversizedResponseBodyWithoutContentLength(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	prefix := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`
	padding := make([]byte, 70<<10) // 70 KiB, above maxCaptureBodyBytes
	for i := range padding {
		padding[i] = 'x'
	}
	wantBody := append([]byte(prefix), padding...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(wantBody)
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, wantBody, gotBody)
	assert.Empty(t, bag.Snapshot())
}

type trackCloseReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackCloseReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestContributorCaptureMiddleware_closesUnderlyingBodyOnOversizedResponse(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	prefix := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`
	padding := make([]byte, 70<<10)
	for i := range padding {
		padding[i] = 'x'
	}
	wantBody := append([]byte(prefix), padding...)

	body := &trackCloseReadCloser{Reader: bytes.NewReader(wantBody)}

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Request:    req,
		}, nil
	})
	rt := newContributorCaptureMiddleware(next, config, &logger)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	_, err = io.Copy(io.Discard, res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.True(t, body.closed)
	assert.Empty(t, bag.Snapshot())
}

func TestContributorCaptureMiddleware_capturesNativeTestAPIFlow(t *testing.T) {
	const (
		orgID     = "11111111-1111-4111-8111-111111111111"
		jobID     = "22222222-2222-4222-8222-222222222222"
		testID    = "44444444-4444-4444-8444-444444444444"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/orgs/"+orgID+"/tests":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"publish_report":true`)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write([]byte(`{"data":{"id":"` + jobID + `"}}`))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/orgs/"+orgID+"/test_jobs/"+jobID:
			w.WriteHeader(http.StatusSeeOther)
			_, err := w.Write([]byte(testJobRedirectBody(testID)))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/orgs/"+orgID+"/tests/"+testID:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{
				"data": {
					"attributes": {
						"state": {"execution": "completed"},
						"subject_locators": [
							{"type": "project_entity", "project_id": "` + projectID + `"}
						]
					}
				}
			}`))
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &zerolog.Logger{})

	createBody := []byte(`{"data":{"attributes":{"config":{"publish_report":true,"scan_config":{"sca":{}}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/vnd.api+json")
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())

	jobReq, err := http.NewRequest(http.MethodGet, server.URL+"/orgs/"+orgID+"/test_jobs/"+jobID, http.NoBody)
	require.NoError(t, err)
	jobRes, err := rt.RoundTrip(jobReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, jobRes.StatusCode)
	require.NoError(t, jobRes.Body.Close())

	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/orgs/"+orgID+"/tests/"+testID, http.NoBody)
	require.NoError(t, err)
	getRes, err := rt.RoundTrip(getReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getRes.StatusCode)
	require.NoError(t, getRes.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, capture.CapabilityOSS, records[0].Capability)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_capturesNativeMonitorTestAPIFlow(t *testing.T) {
	const (
		orgID     = "11111111-1111-4111-8111-111111111111"
		jobID     = "22222222-2222-4222-8222-222222222222"
		testID    = "44444444-4444-4444-8444-444444444444"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/hidden/orgs/"+orgID+"/tests":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"monitor":true`)
			assert.NotContains(t, string(body), `"publish_report":true`)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write([]byte(`{"data":{"id":"` + jobID + `"}}`))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/hidden/orgs/"+orgID+"/test_jobs/"+jobID:
			w.WriteHeader(http.StatusSeeOther)
			_, err := w.Write([]byte(testJobRedirectBody(testID)))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/hidden/orgs/"+orgID+"/tests/"+testID:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{
				"data": {
					"attributes": {
						"state": {"execution": "completed"},
						"subject_locators": [
							{"type": "project_entity", "project_id": "` + projectID + `"}
						]
					}
				}
			}`))
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &zerolog.Logger{})

	createBody := []byte(`{"data":{"attributes":{"config":{"monitor":true,"scan_config":{"sca":{}}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/vnd.api+json")
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())

	jobReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/test_jobs/"+jobID, http.NoBody)
	require.NoError(t, err)
	jobRes, err := rt.RoundTrip(jobReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, jobRes.StatusCode)
	require.NoError(t, jobRes.Body.Close())

	getReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID, http.NoBody)
	require.NoError(t, err)
	getRes, err := rt.RoundTrip(getReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getRes.StatusCode)
	require.NoError(t, getRes.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, capture.CapabilityOSS, records[0].Capability)
	assert.Equal(t, projectID, records[0].EntityID)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_sealsSessionAfterFirstCapture(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			"uri": "https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	capture.ResetCommandSession()
	t.Cleanup(capture.ResetCommandSession)

	notified := false
	capture.RegisterFirstRecordHandler(func() {
		notified = true
	})

	config := captureEnabledConfig(server.URL)
	capture.EnsureCommandSession(".")

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.True(t, notified)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_capturesCodeHiddenTestAPIFlow(t *testing.T) {
	const (
		orgID     = "11111111-1111-4111-8111-111111111111"
		jobID     = "22222222-2222-4222-8222-222222222222"
		testID    = "44444444-4444-4444-8444-444444444444"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/hidden/orgs/"+orgID+"/tests":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"report":true`)
			w.WriteHeader(http.StatusCreated)
			_, err = w.Write([]byte(`{"data":{"id":"` + jobID + `"}}`))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/hidden/orgs/"+orgID+"/test_jobs/"+jobID:
			w.WriteHeader(http.StatusSeeOther)
			_, err := w.Write([]byte(testJobRedirectBody(testID)))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/hidden/orgs/"+orgID+"/tests/"+testID+"/components":
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{
				"data": [{
					"attributes": {
						"type": "sast",
						"success": true,
						"webui": {"project_id": "` + projectID + `"}
					}
				}]
			}`))
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	capture.ResetCommandSession()
	t.Cleanup(capture.ResetCommandSession)

	config := captureEnabledConfig(server.URL)
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &zerolog.Logger{}, func() string {
		return "code test --report"
	})

	createBody := []byte(`{"data":{"type":"test","attributes":{"configuration":{"output":{"report":true,"project_name":"billing-test-goof"}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/vnd.api+json")
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())

	jobReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/test_jobs/"+jobID, http.NoBody)
	require.NoError(t, err)
	jobRes, err := rt.RoundTrip(jobReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, jobRes.StatusCode)
	require.NoError(t, jobRes.Body.Close())

	componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
	require.NoError(t, err)
	componentsRes, err := rt.RoundTrip(componentsReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, componentsRes.StatusCode)
	require.NoError(t, componentsRes.Body.Close())

	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, capture.CapabilityCode, records[0].Capability)
	assert.Equal(t, projectID, records[0].EntityID)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_capturesCodeLegacyDeeproxyReport(t *testing.T) {
	const (
		reportID  = "55555555-5555-4555-8555-555555555555"
		projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/report/"+reportID, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{
			"status": "COMPLETE",
			"uploadResult": {
				"projectId": "` + projectID + `",
				"snapshotId": "28831237-953d-4baa-ba5f-2a6b01ba5b94"
			}
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	capture.ResetCommandSession()
	t.Cleanup(capture.ResetCommandSession)

	config := captureEnabledConfig(server.URL)
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &zerolog.Logger{}, func() string {
		return "code test --report"
	})

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report/"+reportID, http.NoBody)
	require.NoError(t, err)
	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NoError(t, res.Body.Close())

	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, capture.CapabilityCode, records[0].Capability)
	assert.Equal(t, projectID, records[0].EntityID)
	assert.Equal(t, capture.EntityTypeProject, records[0].EntityType)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_capturesCodeLegacyDeeproxyReport_gzip(t *testing.T) {
	const (
		reportID  = "55555555-5555-4555-8555-555555555555"
		projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	)

	plainBody := []byte(`{
		"status": "COMPLETE",
		"uploadResult": {
			"projectId": "` + projectID + `",
			"snapshotId": "28831237-953d-4baa-ba5f-2a6b01ba5b94"
		}
	}`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := writer.Write(plainBody)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/report/"+reportID, r.URL.Path)
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(compressed.Bytes())
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	capture.ResetCommandSession()
	t.Cleanup(capture.ResetCommandSession)

	config := captureEnabledConfig(server.URL)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	rt := newContributorCaptureMiddleware(transport, config, &zerolog.Logger{}, func() string {
		return "code test --report"
	})

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report/"+reportID, http.NoBody)
	require.NoError(t, err)
	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, compressed.Bytes(), gotBody)

	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, capture.CapabilityCode, records[0].Capability)
	assert.Equal(t, projectID, records[0].EntityID)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_capturesCodeLegacyDeeproxyReport_oversizedBody(t *testing.T) {
	const (
		reportID  = "55555555-5555-4555-8555-555555555555"
		projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	)
	prefix := `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `","snapshotId":"28831237-953d-4baa-ba5f-2a6b01ba5b94"},"analysisResult":`
	padding := make([]byte, 70<<10)
	for i := range padding {
		padding[i] = 'x'
	}
	responseBody := append(append([]byte(prefix), padding...), '}')

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/report/"+reportID, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(responseBody)
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	capture.ResetCommandSession()
	t.Cleanup(capture.ResetCommandSession)

	config := captureEnabledConfig(server.URL)
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &zerolog.Logger{}, func() string {
		return "code test --report"
	})

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report/"+reportID, http.NoBody)
	require.NoError(t, err)
	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, responseBody, gotBody)

	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_capturesAIBOMUploadRevisionID(t *testing.T) {
	const (
		orgID      = "11111111-1111-4111-8111-111111111111"
		revisionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	)

	uploadBody := []byte(`{
		"data": {
			"type": "ai_bom_file_upload",
			"attributes": {
				"upload_revision_id": "` + revisionID + `",
				"repo_name": "python-chatbot"
			}
		}
	}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/rest/orgs/"+orgID+"/ai_boms/upload", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.JSONEq(t, string(uploadBody), string(body))
		w.WriteHeader(http.StatusAccepted)
		_, err = w.Write([]byte(`{"data":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","type":"ai_bom_job"}}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger, func() string {
		return "aibom --upload"
	})

	req, err := http.NewRequest(http.MethodPost, server.URL+"/rest/orgs/"+orgID+"/ai_boms/upload", bytes.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	require.NoError(t, res.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, revisionID, records[0].EntityID)
	assert.Equal(t, capture.EntityTypeRevision, records[0].EntityType)
	assert.Equal(t, capture.CapabilityAIBOM, records[0].Capability)
	assert.True(t, capture.IsSessionSealed())
}

func TestContributorCaptureMiddleware_capturesAIBOMUploadRevisionID_emptyResponseBody(t *testing.T) {
	const (
		orgID      = "11111111-1111-4111-8111-111111111111"
		revisionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	)

	uploadBody := []byte(`{
		"data": {
			"type": "ai_bom_file_upload",
			"attributes": {
				"upload_revision_id": "` + revisionID + `",
				"repo_name": "python-chatbot"
			}
		}
	}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/rest/orgs/"+orgID+"/ai_boms/upload", r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	config := captureEnabledConfig(server.URL)
	bag := openCaptureSession(t)

	logger := zerolog.Nop()
	rt := newContributorCaptureMiddleware(http.DefaultTransport, config, &logger, func() string {
		return "aibom --upload"
	})

	req, err := http.NewRequest(http.MethodPost, server.URL+"/rest/orgs/"+orgID+"/ai_boms/upload", bytes.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, res.StatusCode)
	require.NoError(t, res.Body.Close())

	records := bag.Snapshot()
	require.Len(t, records, 1)
	assert.Equal(t, revisionID, records[0].EntityID)
	assert.True(t, capture.IsSessionSealed())
}
