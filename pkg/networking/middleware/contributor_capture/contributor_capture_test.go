package contributor_capture_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributors"
	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestContributorCaptureMiddleware_capturesProjectIDsFromVariousEndpoints(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		path              string
		responseBody      func(ids ...string) string
		expectedProjectID []string
	}{
		{
			name:   "monitor",
			method: http.MethodPut,
			path:   "/v1/monitor/npm",
			responseBody: func(ids ...string) string {
				return `{
					"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
					"uri": "https://app.snyk.io/org/acme/project/` + ids[0] + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
				}`
			},
			expectedProjectID: []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
		},
		{
			name:   "iac share",
			method: http.MethodPost,
			path:   "/v1/iac-cli-share-results",
			responseBody: func(ids ...string) string {
				return `{
					"./main.tf": "` + ids[0] + `",
					"./other.tf": "` + ids[1] + `",
					"ok": true
				}`
			},
			expectedProjectID: []string{"dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.method, r.Method)
				assert.Equal(t, tt.path, r.URL.Path)
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(tt.responseBody(tt.expectedProjectID...)))
				require.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			sink := newFakeSink()
			logger := zerolog.Nop()
			rt := newMiddleware(http.DefaultTransport, sink, &logger)

			req, err := http.NewRequest(tt.method, server.URL+tt.path, http.NoBody)
			require.NoError(t, err)

			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, http.StatusOK, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.NotEmpty(t, body)
			require.NoError(t, res.Body.Close())

			records := sink.Records()
			require.Len(t, records, len(tt.expectedProjectID))
			assert.Equal(t, contributors.EntityTypeProject, records[0].EntityType)
			if len(records) == 1 {
				assert.Equal(t, tt.expectedProjectID[0], records[0].EntityID)
			} else {
				assert.ElementsMatch(t, tt.expectedProjectID, []string{records[0].EntityID, records[1].EntityID})
			}
		})
	}
}

func TestContributorCaptureMiddleware_skipsNonSuccessResponses(t *testing.T) {
	monitorBody := `{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`

	tests := []struct {
		statusCode int
	}{
		{statusCode: http.StatusNotFound},
		{statusCode: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, err := w.Write([]byte(monitorBody))
				require.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			sink := newFakeSink()
			logger := zerolog.Nop()
			rt := newMiddleware(http.DefaultTransport, sink, &logger)

			req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
			require.NoError(t, err)

			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tt.statusCode, res.StatusCode)
			require.NoError(t, res.Body.Close())

			assert.Empty(t, sink.Records())
		})
	}
}

func TestContributorCaptureMiddleware_capturesDespiteInflatedContentLength(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	monitorBody := []byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)

	sink := newFakeSink()
	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: 70000,
			Body:          io.NopCloser(bytes.NewReader(monitorBody)),
			Request:       req,
		}, nil
	})
	rt := newMiddleware(next, sink, &logger)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_preservesOversizedResponseBodyWithoutContentLength(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	prefix := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`
	wantBody := append([]byte(prefix), bytes.Repeat([]byte("x"), 70<<10)...) // 70 KiB, above maxCaptureBodyBytes

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(wantBody)
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	sink := newFakeSink()
	logger := zerolog.Nop()
	rt := newMiddleware(http.DefaultTransport, sink, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, wantBody, gotBody)
	assert.Empty(t, sink.Records())
}

func TestContributorCaptureMiddleware_closesUnderlyingBodyOnOversizedResponse(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	prefix := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`
	wantBody := append([]byte(prefix), bytes.Repeat([]byte("x"), 70<<10)...)

	body := &trackCloseReadCloser{Reader: bytes.NewReader(wantBody)}

	sink := newFakeSink()
	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Request:    req,
		}, nil
	})
	rt := newMiddleware(next, sink, &logger)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	_, err = io.Copy(io.Discard, res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.True(t, body.closed)
	assert.Empty(t, sink.Records())
}

func TestContributorCaptureMiddleware_matchesHostIgnoringPort(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	monitorBody := []byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)

	sink := newFakeSink()
	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(monitorBody)),
			Request:    req,
		}, nil
	})
	rt := newMiddleware(next, sink, &logger)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io:443/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_capturesTestAPIComponentsFlow(t *testing.T) {
	const (
		orgID     = "11111111-1111-4111-8111-111111111111"
		testID    = "22222222-2222-4222-8222-222222222222"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/hidden/orgs/"+orgID+"/tests":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"report":true`)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write([]byte(`{"data":{"id":"` + testID + `"}}`))
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
	sink := newFakeSink()
	rt := newMiddleware(http.DefaultTransport, sink, &zerolog.Logger{})

	createBody := []byte(`{"data":{"attributes":{"configuration":{"output":{"report":true}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/vnd.api+json")
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())

	assert.Empty(t, sink.Records(), "create-test response has no project ID and must not reach the sink")

	componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
	require.NoError(t, err)
	componentsRes, err := rt.RoundTrip(componentsReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, componentsRes.StatusCode)
	require.NoError(t, componentsRes.Body.Close())

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_doesNotTruncateOversizedCreateTestRequestBody(t *testing.T) {
	const orgID = "44444444-4444-4444-8444-444444444444"

	padding := strings.Repeat("x", 70<<10) // 70 KiB, above maxCaptureBodyBytes
	createBody := []byte(`{"data":{"attributes":{"configuration":{"output":{"report":true}},"note":"` + padding + `"}}}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, createBody, received, "the real outgoing request body must reach the server untruncated")
		w.WriteHeader(http.StatusAccepted)
		_, err = w.Write([]byte(`{"data":{"id":"44444444-4444-4444-8444-444444444444"}}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	sink := newFakeSink()
	rt := newMiddleware(http.DefaultTransport, sink, &zerolog.Logger{})

	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())
}

func TestContributorCaptureMiddleware_doesNotCaptureComponents_whenNeverCreatedWithPublishReport(t *testing.T) {
	const (
		orgID     = "55555555-5555-4555-8555-555555555555"
		testID    = "55555555-5555-4555-8555-555555555555"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	t.Cleanup(server.Close)
	sink := newFakeSink()
	rt := newMiddleware(http.DefaultTransport, sink, &zerolog.Logger{})

	// No create-test call happened for this test ID, so it was never marked pending.
	componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
	require.NoError(t, err)
	componentsRes, err := rt.RoundTrip(componentsReq)
	require.NoError(t, err)
	require.NoError(t, componentsRes.Body.Close())

	assert.Empty(t, sink.Records())
}

func TestContributorCaptureMiddleware_componentsPollingSurvivesThenStopsAfterSuccess(t *testing.T) {
	const (
		orgID     = "66666666-6666-4666-8666-666666666666"
		testID    = "66666666-6666-4666-8666-666666666666"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	successBody := []byte(`{
		"data": [{
			"attributes": {
				"type": "sast",
				"success": true,
				"webui": {"project_id": "` + projectID + `"}
			}
		}]
	}`)

	pollCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/hidden/orgs/"+orgID+"/tests":
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write([]byte(`{"data":{"id":"` + testID + `"}}`))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == "/hidden/orgs/"+orgID+"/tests/"+testID+"/components":
			pollCount++
			w.WriteHeader(http.StatusOK)
			if pollCount < 3 {
				_, err := w.Write([]byte(`{"data":[]}`))
				require.NoError(t, err)
				return
			}
			_, err := w.Write(successBody)
			require.NoError(t, err)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	sink := newFakeSink()
	rt := newMiddleware(http.DefaultTransport, sink, &zerolog.Logger{})

	createBody := []byte(`{"data":{"attributes":{"configuration":{"output":{"report":true}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.NoError(t, createRes.Body.Close())

	// Polls 1-2: unsuccessful, must not evict the pending test. Poll 3:
	// succeeds and captures. Poll 4: succeeds again but must not re-capture.
	for range 4 {
		componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
		require.NoError(t, err)
		componentsRes, err := rt.RoundTrip(componentsReq)
		require.NoError(t, err)
		require.NoError(t, componentsRes.Body.Close())
	}

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_recoversFromSinkPanic_onResponse(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	logger := zerolog.Nop()
	rt := newMiddleware(http.DefaultTransport, panicSink{}, &logger)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err, "a panicking sink must not propagate out of RoundTrip")
	require.NotNil(t, res)
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_capturesAIBomUploadRevisionIDFromRequestBody(t *testing.T) {
	const (
		orgID      = "d5341082-085f-4458-a223-90c16aae2435"
		revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"
	)
	uploadBody := `{"data":{"attributes":{"repo_name":"acme/app","upload_revision_id":"` + revisionID + `"},"type":"ai_bom_file_upload"}}`

	var gotRequestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotRequestBody = body
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)
	sink := newFakeSink()
	logger := zerolog.Nop()
	rt := newMiddleware(http.DefaultTransport, sink, &logger)

	url := server.URL + "/rest/orgs/" + orgID + "/ai_boms/upload?version=2024-10-15"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, uploadBody, string(gotRequestBody), "peeking the body must not stop it reaching the server")

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, contributors.EntityTypeRevision, records[0].EntityType)
	assert.Equal(t, revisionID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_leavesAIBomUploadResponseUntouched(t *testing.T) {
	const revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"
	uploadBody := `{"data":{"attributes":{"upload_revision_id":"` + revisionID + `"},"type":"ai_bom_file_upload"}}`

	sink := newFakeSink()
	logger := zerolog.Nop()
	body := &trackCloseReadCloser{Reader: strings.NewReader(`{"data":{"id":"ignored"}}`)}
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: body, Request: req}, nil
	})
	rt := newMiddleware(next, sink, &logger)

	url := "https://api.snyk.io/rest/orgs/d5341082-085f-4458-a223-90c16aae2435/ai_boms/upload"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	// capture completes from the request alone, so the response must pass
	// through unread and unclosed
	assert.False(t, body.closed, "response body must not be consumed for a request-only capture")
	require.Len(t, sink.Records(), 1)
	assert.Equal(t, revisionID, sink.Records()[0].EntityID)

	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_recordsNothingWhenResponseHasNoProjectID(t *testing.T) {
	sink := newFakeSink()
	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)), // no uri, so no project ID
			Request:    req,
		}, nil
	})
	rt := newMiddleware(next, sink, &logger)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Empty(t, sink.Records(), "an unparseable ID must not be recorded as an empty entity")
}

func TestContributorCaptureMiddleware_recordsNothingWhenAIBomUploadHasNoRevisionID(t *testing.T) {
	sink := newFakeSink()
	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: http.NoBody, Request: req}, nil
	})
	rt := newMiddleware(next, sink, &logger)

	url := "https://api.snyk.io/rest/orgs/d5341082-085f-4458-a223-90c16aae2435/ai_boms/upload"
	uploadBody := `{"data":{"attributes":{"repo_name":"acme/app"},"type":"ai_bom_file_upload"}}`
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Empty(t, sink.Records(), "a missing revision ID must not be recorded as an empty entity")
}

func TestContributorCaptureMiddleware_capturesDeeproxyReportProjectID(t *testing.T) {
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
				"projectId": "` + projectID + `"
			}
		}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	sink := newFakeSink()
	rt := newMiddleware(http.DefaultTransport, sink, &zerolog.Logger{})

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report/"+reportID, http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_capturesTruncatedDeeproxyReportPrefix(t *testing.T) {
	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	prefix := `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"` + `,"analysisResult":{"type":"sarif","data":"`
	wantBody := append([]byte(prefix), bytes.Repeat([]byte("x"), 70<<10)...)

	sink := newFakeSink()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(wantBody)),
			Request:    req,
		}, nil
	})
	rt := newMiddleware(next, sink, &zerolog.Logger{})

	req, err := http.NewRequest(http.MethodGet, "https://api.snyk.io/report/55555555-5555-4555-8555-555555555555", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

func TestContributorCaptureMiddleware_capturesTestAPIComponentsFlowWithLegacyPublishReport(t *testing.T) {
	const (
		orgID     = "77777777-7777-4777-8777-777777777777"
		testID    = "88888888-8888-4888-8888-888888888888"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/hidden/orgs/"+orgID+"/tests":
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), `"publish_report":true`)
			w.WriteHeader(http.StatusAccepted)
			_, err = w.Write([]byte(`{"data":{"id":"` + testID + `"}}`))
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
	sink := newFakeSink()
	rt := newMiddleware(http.DefaultTransport, sink, &zerolog.Logger{})

	createBody := []byte(`{"data":{"attributes":{"config":{"publish_report":true,"scan_config":{"sast":{}}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.NoError(t, createRes.Body.Close())

	componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
	require.NoError(t, err)
	componentsRes, err := rt.RoundTrip(componentsReq)
	require.NoError(t, err)
	require.NoError(t, componentsRes.Body.Close())

	records := sink.Records()
	require.Len(t, records, 1)
	assert.Equal(t, projectID, records[0].EntityID)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newMiddleware(rt http.RoundTripper, sink cc.Sink, logger *zerolog.Logger) http.RoundTripper {
	return cc.NewContributorCaptureMiddleware(sink, logger)(rt)
}

type panicSink struct{}

func (panicSink) RecordEntity(_ contributors.EntityType, _ string) {
	panic("boom")
}

type trackCloseReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackCloseReadCloser) Close() error {
	r.closed = true
	return nil
}
