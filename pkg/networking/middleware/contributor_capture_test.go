package middleware_test

import (
	"bytes"
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
		testID    = "22222222-2222-4222-8222-222222222222"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/orgs/"+orgID+"/tests":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"publish_report":true`)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write([]byte(`{"data":{"id":"` + testID + `"}}`))
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
