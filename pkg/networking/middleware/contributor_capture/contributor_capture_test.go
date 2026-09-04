package contributor_capture_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
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
			rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
			for _, id := range tt.expectedProjectID {
				sink.EXPECT().RecordEntity(contributors.EntityTypeProject, id)
			}

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
		})
	}
}

func TestContributorCaptureMiddleware_skipsUnmatchedRequests(t *testing.T) {
	const (
		projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		orgID     = "11111111-1111-4111-8111-111111111111"
		testID    = "22222222-2222-4222-8222-222222222222"
		reportID  = "55555555-5555-4555-8555-555555555555"
	)
	monitorBody := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`
	reportBody := `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"}}`
	componentsBody := string(componentsSuccessBody(projectID))

	// Every case points API_URL at api.snyk.io while the request goes to an
	// unrelated host, so a path-only match would leak the project ID.
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"monitor", http.MethodPut, "/v1/monitor/npm", monitorBody},
		{"iac share", http.MethodPost, "/v1/iac-cli-share-results", `{"./main.tf":"` + projectID + `","ok":true}`},
		{"deeproxy report", http.MethodGet, "/report/" + reportID, reportBody},
		{"components", http.MethodGet, "/hidden/orgs/" + orgID + "/tests/" + testID + "/components", componentsBody},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(tt.body))
				require.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			// Anything reaching the sink here is the leak we're guarding against.
			rt, _ := newTestMiddleware(t, http.DefaultTransport, "https://api.snyk.io")

			req, err := http.NewRequest(tt.method, server.URL+tt.path, http.NoBody)
			require.NoError(t, err)

			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.NoError(t, res.Body.Close())
		})
	}
}

func TestContributorCaptureMiddleware_capturesOnAuthenticatedSubdomain(t *testing.T) {
	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	reportBody := gzipBody(t, []byte(`{"status":"COMPLETE","uploadResult":{"projectId":"`+projectID+`"}}`))

	config := hostConfig("https://api.snyk.io")
	config.Set(configuration.AUTHENTICATION_SUBDOMAINS, []string{"deeproxy"})

	sink := NewMockSink(gomock.NewController(t))
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)
	logger := zerolog.Nop()
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(reportBody)),
			Request:    req,
		}, nil
	})
	rt := newMiddleware(next, config, sink, &logger)

	req, err := http.NewRequest(http.MethodGet, "https://deeproxy.snyk.io/report/55555555-5555-4555-8555-555555555555", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
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
			rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
			sink.EXPECT().RecordMiss(contributors.MissErrorStatus)

			req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
			require.NoError(t, err)

			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tt.statusCode, res.StatusCode)
			require.NoError(t, res.Body.Close())
		})
	}
}

func TestContributorCaptureMiddleware_capturesDespiteInflatedContentLength(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	monitorBody := []byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)

	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: 70000,
			Body:          io.NopCloser(bytes.NewReader(monitorBody)),
			Request:       req,
		}, nil
	})
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())
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
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	sink.EXPECT().RecordMiss(contributors.MissBodyTooLarge)

	req, err := http.NewRequest(http.MethodPut, server.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, wantBody, gotBody)
}

func TestContributorCaptureMiddleware_closesUnderlyingBodyOnOversizedResponse(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	prefix := `{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`
	wantBody := append([]byte(prefix), bytes.Repeat([]byte("x"), 70<<10)...)

	body := &trackCloseReadCloser{Reader: bytes.NewReader(wantBody)}

	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Request:    req,
		}, nil
	})
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordMiss(contributors.MissBodyTooLarge)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	_, err = io.Copy(io.Discard, res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.True(t, body.closed)
}

func TestContributorCaptureMiddleware_matchesHostIgnoringPort(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	monitorBody := []byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)

	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(monitorBody)),
			Request:    req,
		}, nil
	})
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io:443/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_capturesTestAPIComponentsFlow(t *testing.T) {
	const (
		orgID     = "11111111-1111-4111-8111-111111111111"
		testID    = "22222222-2222-4222-8222-222222222222"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := newTestComponentsServer(t, componentsServerOpts{
		orgID: orgID, testID: testID, projectID: projectID,
		wantCreateBodyContains: `"report":true`,
	})
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)

	createBody := []byte(`{"data":{"attributes":{"configuration":{"output":{"report":true}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createReq.Header.Set("Content-Type", "application/vnd.api+json")
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())

	// Set after the create round trip on purpose. Create carries no project ID,
	// so anything reaching the sink before now should blow up.
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)

	componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
	require.NoError(t, err)
	componentsRes, err := rt.RoundTrip(componentsReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, componentsRes.StatusCode)
	require.NoError(t, componentsRes.Body.Close())
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
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	// The truncated peek loses the report flag, leaving us unable to say whether
	// this test was one we should have followed.
	sink.EXPECT().RecordMiss(contributors.MissBodyUnreadable)

	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, createRes.StatusCode)
	require.NoError(t, createRes.Body.Close())
}

// A test created without publish_report can never yield an entity, so neither it
// nor the polls that follow it are capture failures. Every non-reporting scan
// takes this path, so reporting them would drown the failures worth seeing.
func TestContributorCaptureMiddleware_reportsNoMissForATestThatDeclinedToPublish(t *testing.T) {
	const (
		orgID     = "77777777-7777-4777-8777-777777777777"
		testID    = "77777777-7777-4777-8777-777777777777"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := newTestComponentsServer(t, componentsServerOpts{orgID: orgID, testID: testID, projectID: projectID})
	// A strict mock with no expectations: any call at all fails the test.
	rt, _ := newTestMiddleware(t, http.DefaultTransport, server.URL)

	createBody := []byte(`{"data":{"attributes":{"configuration":{"output":{"report":false}}}}}`)
	createReq, err := http.NewRequest(http.MethodPost, server.URL+"/hidden/orgs/"+orgID+"/tests", bytes.NewReader(createBody))
	require.NoError(t, err)
	createRes, err := rt.RoundTrip(createReq)
	require.NoError(t, err)
	require.NoError(t, createRes.Body.Close())

	for range 2 {
		componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
		require.NoError(t, err)
		componentsRes, err := rt.RoundTrip(componentsReq)
		require.NoError(t, err)
		require.NoError(t, componentsRes.Body.Close())
	}
}

func TestContributorCaptureMiddleware_doesNotCaptureComponents_whenTheTestWasNeverCreated(t *testing.T) {
	const (
		orgID     = "55555555-5555-4555-8555-555555555555"
		testID    = "55555555-5555-4555-8555-555555555555"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(componentsSuccessBody(projectID))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	// Never having seen the create means we lost a test we should have followed.
	sink.EXPECT().RecordMiss(contributors.MissNoEntity)

	// No create-test call happened for this test ID, so it was never marked pending.
	componentsReq, err := http.NewRequest(http.MethodGet, server.URL+"/hidden/orgs/"+orgID+"/tests/"+testID+"/components", http.NoBody)
	require.NoError(t, err)
	componentsRes, err := rt.RoundTrip(componentsReq)
	require.NoError(t, err)
	require.NoError(t, componentsRes.Body.Close())
}

func TestContributorCaptureMiddleware_componentsPollingSurvivesThenStopsAfterSuccess(t *testing.T) {
	const (
		orgID     = "66666666-6666-4666-8666-666666666666"
		testID    = "66666666-6666-4666-8666-666666666666"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := newTestComponentsServer(t, componentsServerOpts{
		orgID: orgID, testID: testID, projectID: projectID,
		emptyPolls: 2,
	})
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID).Times(1)
	// Polls 1-2 carry no project ID while the test is still pending. Poll 4 arrives
	// after the capture, which is expected rather than a failure.
	sink.EXPECT().RecordMiss(contributors.MissNoEntity).Times(2)

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
}

func TestContributorCaptureMiddleware_recoversFromSinkPanic_onRequest(t *testing.T) {
	const (
		orgID      = "d5341082-085f-4458-a223-90c16aae2435"
		revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"
	)
	uploadBody := `{"data":{"attributes":{"upload_revision_id":"` + revisionID + `"},"type":"ai_bom_file_upload"}}`

	// AI-BOM upload records before the request is sent, so the panic escapes on
	// the request path rather than the response path.
	var gotRequestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotRequestBody = body
		w.WriteHeader(http.StatusCreated)
		_, err = w.Write([]byte(`{"data":{"id":"ok"}}`))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	logger := zerolog.Nop()
	rt := newMiddleware(http.DefaultTransport, hostConfig(server.URL), panickingSink(t), &logger)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/rest/orgs/"+orgID+"/ai_boms/upload", strings.NewReader(uploadBody))
	require.NoError(t, err)

	var res *http.Response
	require.NotPanics(t, func() {
		res, err = rt.RoundTrip(req)
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, http.StatusCreated, res.StatusCode)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, uploadBody, string(gotRequestBody), "the request must still be sent intact")
	assert.JSONEq(t, `{"data":{"id":"ok"}}`, string(gotBody))
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
	rt := newMiddleware(http.DefaultTransport, hostConfig(server.URL), panickingSink(t), &logger)

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
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	sink.EXPECT().RecordEntity(contributors.EntityTypeRevision, revisionID)

	url := server.URL + "/rest/orgs/" + orgID + "/ai_boms/upload?version=2024-10-15"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, uploadBody, string(gotRequestBody), "peeking the body must not stop it reaching the server")
}

func TestContributorCaptureMiddleware_leavesAIBomUploadResponseUntouched(t *testing.T) {
	const revisionID = "19d7450b-886f-4029-9b60-1b309b85b800"
	uploadBody := `{"data":{"attributes":{"upload_revision_id":"` + revisionID + `"},"type":"ai_bom_file_upload"}}`

	body := &trackCloseReadCloser{Reader: strings.NewReader(`{"data":{"id":"ignored"}}`)}
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: body, Request: req}, nil
	})
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordEntity(contributors.EntityTypeRevision, revisionID)

	url := "https://api.snyk.io/rest/orgs/d5341082-085f-4458-a223-90c16aae2435/ai_boms/upload"
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, res)

	// capture completes from the request alone, so the response must pass
	// through unread and unclosed
	assert.False(t, body.closed, "response body must not be consumed for a request-only capture")

	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_recordsNothingWhenResponseHasNoProjectID(t *testing.T) {
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)), // no uri, so no project ID
			Request:    req,
		}, nil
	})
	// A junk ID should be dropped, not recorded as an empty entity.
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordMiss(contributors.MissNoEntity)

	req, err := http.NewRequest(http.MethodPut, "https://api.snyk.io/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_recordsNothingWhenAIBomUploadHasNoRevisionID(t *testing.T) {
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusCreated, Body: http.NoBody, Request: req}, nil
	})
	// A missing revision ID should be dropped too, not recorded empty.
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordMiss(contributors.MissNoEntity)

	url := "https://api.snyk.io/rest/orgs/d5341082-085f-4458-a223-90c16aae2435/ai_boms/upload"
	uploadBody := `{"data":{"attributes":{"repo_name":"acme/app"},"type":"ai_bom_file_upload"}}`
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(uploadBody))
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
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
		_, err := w.Write(gzipBody(t, []byte(`{
			"status": "COMPLETE",
			"uploadResult": {
				"projectId": "`+projectID+`"
			}
		}`)))
		require.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/report/"+reportID, http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_capturesTruncatedDeeproxyReportPrefix(t *testing.T) {
	const projectID = "25bcb5ba-5b16-4f56-8620-4e3a508f67ed"
	prefix := `{"status":"COMPLETE","uploadResult":{"projectId":"` + projectID + `"},"analysisResult":{"type":"sarif","data":"`
	// The padding is incompressible so the body still exceeds maxCaptureBodyBytes
	// once gzipped.
	wantBody := gzipBody(t, append([]byte(prefix), incompressiblePadding(200<<10)...))

	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(wantBody)),
			Request:    req,
		}, nil
	})
	rt, sink := newTestMiddleware(t, next, "https://api.snyk.io")
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)

	req, err := http.NewRequest(http.MethodGet, "https://api.snyk.io/report/55555555-5555-4555-8555-555555555555", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
}

func TestContributorCaptureMiddleware_capturesTestAPIComponentsFlowWithLegacyPublishReport(t *testing.T) {
	const (
		orgID     = "77777777-7777-4777-8777-777777777777"
		testID    = "88888888-8888-4888-8888-888888888888"
		projectID = "33333333-3333-4333-8333-333333333333"
	)

	server := newTestComponentsServer(t, componentsServerOpts{
		orgID: orgID, testID: testID, projectID: projectID,
		wantCreateBodyContains: `"publish_report":true`,
	})
	rt, sink := newTestMiddleware(t, http.DefaultTransport, server.URL)
	sink.EXPECT().RecordEntity(contributors.EntityTypeProject, projectID)

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
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newMiddleware(rt http.RoundTripper, config configuration.Configuration, sink cc.Sink, logger *zerolog.Logger) http.RoundTripper {
	return cc.NewContributorCaptureMiddleware(config, sink, logger)(rt)
}

func hostConfig(apiURL string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, apiURL)
	return config
}

// newTestMiddleware wires the middleware to a mock sink, scoped to apiURL as the known host.
func newTestMiddleware(t *testing.T, next http.RoundTripper, apiURL string) (http.RoundTripper, *MockSink) {
	t.Helper()
	sink := NewMockSink(gomock.NewController(t))
	logger := zerolog.Nop()
	return newMiddleware(next, hostConfig(apiURL), sink, &logger), sink
}

// Times(1) rather than AnyTimes. If the sink never gets called at all, the
// recovery path silently goes untested.
func panickingSink(t *testing.T) *MockSink {
	t.Helper()
	sink := NewMockSink(gomock.NewController(t))
	sink.EXPECT().RecordEntity(gomock.Any(), gomock.Any()).
		Do(func(contributors.EntityType, string) { panic("boom") }).
		Times(1)
	sink.EXPECT().RecordMiss(contributors.MissPanic).Times(1)
	return sink
}

func componentsSuccessBody(projectID string) []byte {
	return []byte(`{
		"data": [{
			"attributes": {
				"type": "sast",
				"success": true,
				"webui": {"project_id": "` + projectID + `"}
			}
		}]
	}`)
}

type componentsServerOpts struct {
	orgID, testID, projectID string
	wantCreateBodyContains   string // "" skips the create-test body assertion
	emptyPolls               int    // components polls answered empty before success
}

// newTestComponentsServer serves the create-test + components-poll pair of the hidden Test API.
func newTestComponentsServer(t *testing.T, opts componentsServerOpts) *httptest.Server {
	t.Helper()
	createPath := "/hidden/orgs/" + opts.orgID + "/tests"
	componentsPath := createPath + "/" + opts.testID + "/components"
	polls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == createPath:
			if opts.wantCreateBodyContains != "" {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Contains(t, string(body), opts.wantCreateBodyContains)
			}
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write([]byte(`{"data":{"id":"` + opts.testID + `"}}`))
			require.NoError(t, err)
		case r.Method == http.MethodGet && r.URL.Path == componentsPath:
			polls++
			w.WriteHeader(http.StatusOK)
			body := componentsSuccessBody(opts.projectID)
			if polls <= opts.emptyPolls {
				body = []byte(`{"data":[]}`)
			}
			_, err := w.Write(body)
			require.NoError(t, err)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

type trackCloseReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackCloseReadCloser) Close() error {
	r.closed = true
	return nil
}

func gzipBody(t *testing.T, plain []byte) []byte {
	t.Helper()

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := writer.Write(plain)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return compressed.Bytes()
}

// incompressiblePadding returns padding which gzip cannot shrink.
func incompressiblePadding(size int) []byte {
	rng := rand.New(rand.NewPCG(1, 2))

	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(rng.Uint32())
	}
	return padding
}
