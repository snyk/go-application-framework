package middleware_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

func Test_ResponseMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/400":
			w.WriteHeader(http.StatusBadRequest)
		case "/404":
			w.WriteHeader(http.StatusNotFound)
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
		case "/429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/jsonapi-SNYK-0003":
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"errors":[{"status":"400","detail":"project found but does not contain a target id","id":"6b86a7a8-9efb-4ed1-b3a2-1ed78ced78a9","title":"Not Found","meta":{"created":"2025-02-21T03:14:00.318931623Z"}}]}`))
			assert.Nil(t, err)
		case "/jsonapi-SNYK-0000":
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"errors":[{"status":"404","detail":"project found but does not contain a target id","id":"6b86a7a8-9efb-4ed1-b3a2-1ed78ced78a9","title":"Not Found","meta":{"created":"2025-02-21T03:14:00.318931623Z"}}]}`))
			assert.Nil(t, err)
		case "/random-error":
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte(`an error happened`))
			assert.Nil(t, err)
		case "/error-catalog":
			errToSend := snyk.NewBadGatewayError("whatever")
			w.WriteHeader(errToSend.StatusCode)
			err := errToSend.MarshalToJSONAPIError(w, "i")
			assert.Nil(t, err)
		default:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("hello"))
			assert.Nil(t, err)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	errHandler := func(err error, ctx context.Context) error {
		return err
	}

	t.Run("no error for 2xx", func(t *testing.T) {
		config := getBaseConfig()
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)

		req := buildRequest(server.URL)
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Nil(t, err)
	})

	t.Run("proper errors for matching status codes", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)

		codes := []int{400, 401, 429, 500}
		for _, code := range codes {
			snykErr := snyk_errors.Error{}
			url := fmt.Sprintf("%s/%d", server.URL, code)
			req := buildRequest(url)
			res, err := rt.RoundTrip(req)

			assert.NotNil(t, res)
			assert.ErrorAs(t, err, &snykErr)
			assert.Equal(t, code, snykErr.StatusCode)
			if code == http.StatusTooManyRequests {
				assert.Equal(t, "SNYK-0001", snykErr.ErrorCode)
				assert.Equal(t, "error", snykErr.Level)
			}

			// observability metadata
			assert.Equal(t, snykErr.Meta["request-id"], "1234")
			assert.Equal(t, snykErr.Meta["request-path"], fmt.Sprintf("/%d", code))
		}
	})

	t.Run("no error if no status code matches", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/404")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Nil(t, err)
	})

	t.Run("should not intercept external urls", func(t *testing.T) {
		config := getBaseConfig()

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/401")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Equal(t, res.StatusCode, http.StatusUnauthorized)
		assert.NoError(t, err)
	})

	t.Run("json api response with SNYK-0003 default", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/jsonapi-SNYK-0003")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Error(t, err)

		actual := snyk_errors.Error{}
		assert.ErrorAs(t, err, &actual)
		assert.Equal(t, snyk.NewBadRequestError("").ErrorCode, actual.ErrorCode)
	})

	t.Run("json api response with SNYK-0000 default", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/jsonapi-SNYK-0000")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Error(t, err)

		actual := snyk_errors.Error{}
		assert.ErrorAs(t, err, &actual)
		assert.Equal(t, cli.NewGeneralCLIFailureError("").ErrorCode, actual.ErrorCode)
	})

	t.Run("error catalog response", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/error-catalog")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Error(t, err)

		expected := snyk.NewBadGatewayError("")
		actual := snyk_errors.Error{}
		assert.ErrorAs(t, err, &actual)

		assert.Equal(t, expected.ErrorCode, actual.ErrorCode)
	})

	t.Run("random error response", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/random-error")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, res.StatusCode)
	})

	t.Run("request error", func(t *testing.T) {
		config := getBaseConfig()

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "0000000")
		res, err := rt.RoundTrip(req)

		assert.Nil(t, res)
		assert.Error(t, err)
	})

	t.Run("no error", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

		// server url is not in the base config, so it's not intercepted
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
		req := buildRequest(server.URL + "/home")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("response body should be consumable after roundtrip", func(t *testing.T) {
		testCases := []struct {
			name        string
			urlPath     string
			expectError bool
		}{
			{
				name:        "no error",
				urlPath:     "",
				expectError: false,
			},
			{
				name:        "with error",
				urlPath:     "/error-catalog",
				expectError: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				config := getBaseConfig()
				config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})

				rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)
				req := buildRequest(server.URL + tc.urlPath)
				res, err := rt.RoundTrip(req)

				assert.NotNil(t, res)
				if tc.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}

				bodyBytes, err := io.ReadAll(res.Body)
				assert.NoError(t, err, "Body should be readable")
				assert.NotEmpty(t, bodyBytes, "Should be able to read body")

				err = res.Body.Close()
				assert.NoError(t, err, "Body should close without errors")
			})
		}
	})
}

func Test_ResponseMiddleware_RateLimitEnrichment(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/429-with-reset":
			w.Header().Set("X-RateLimit-Reset", "300")
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/429-with-huge-reset":
			w.Header().Set("X-RateLimit-Reset", "99999999")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	errHandler := func(err error, ctx context.Context) error {
		return err
	}

	t.Run("with rate-limit headers enriches error", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)

		req := buildRequest(server.URL + "/429-with-reset")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Error(t, err)

		snykErr := snyk_errors.Error{}
		assert.ErrorAs(t, err, &snykErr)
		assert.Equal(t, "SNYK-0001", snykErr.ErrorCode)
		assert.Equal(t, 300, snykErr.Meta["retry-after-seconds"])
		assert.Contains(t, snykErr.Detail, "Retry after:")
		assert.Contains(t, snykErr.Description, "shared across all usage of this token")
	})

	t.Run("delay beyond cap skips retry detail but keeps description", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)

		req := buildRequest(server.URL + "/429-with-huge-reset")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Error(t, err)

		snykErr := snyk_errors.Error{}
		assert.ErrorAs(t, err, &snykErr)
		assert.Equal(t, "SNYK-0001", snykErr.ErrorCode)
		assert.Nil(t, snykErr.Meta["retry-after-seconds"])
		assert.Contains(t, snykErr.Description, "shared across all usage of this token")
	})

	t.Run("without rate-limit headers still has actionable description", func(t *testing.T) {
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{server.URL})
		rt := middleware.NewReponseMiddleware(http.DefaultTransport, config, errHandler)

		req := buildRequest(server.URL + "/429")
		res, err := rt.RoundTrip(req)

		assert.NotNil(t, res)
		assert.Error(t, err)

		snykErr := snyk_errors.Error{}
		assert.ErrorAs(t, err, &snykErr)
		assert.Equal(t, "SNYK-0001", snykErr.ErrorCode)
		assert.Contains(t, snykErr.Description, "shared across all usage of this token")
		assert.Nil(t, snykErr.Meta["retry-after-seconds"])
	})
}

func Test_getErrorList_ClosesOriginalBody(t *testing.T) {
	validErrorBody := `{"jsonapi":{"version":"1.0"},"errors":[{"status":"400","detail":"bad request","title":"Bad Request"}]}`

	t.Run("closes body on valid JSON API error", func(t *testing.T) {
		res, tb := newTrackingResponse(http.StatusBadRequest, validErrorBody)
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})

		err := middleware.HandleResponse(res, config)
		assert.Error(t, err)
		assert.True(t, tb.closed, "original body must be closed after reading")
	})

	t.Run("closes body on invalid JSON", func(t *testing.T) {
		res, tb := newTrackingResponse(http.StatusInternalServerError, "not json")
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})

		err := middleware.HandleResponse(res, config)
		assert.Error(t, err)
		assert.True(t, tb.closed, "original body must be closed even when JSON parsing fails")
	})

	t.Run("body is readable after HandleResponse", func(t *testing.T) {
		res, tb := newTrackingResponse(http.StatusBadRequest, validErrorBody)
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})

		err := middleware.HandleResponse(res, config)
		assert.Error(t, err)
		assert.True(t, tb.closed, "original body must be closed")

		bodyBytes, err := io.ReadAll(res.Body)
		assert.NoError(t, err, "replacement body should be readable")
		assert.Equal(t, validErrorBody, string(bodyBytes))
	})

	t.Run("nil body returns empty error list without panic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://api.snyk.io/test", nil)
		res := &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       nil,
			Header:     http.Header{},
			Request:    req,
		}
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})

		err := middleware.HandleResponse(res, config)
		assert.Error(t, err)
	})

	t.Run("empty body returns empty error list", func(t *testing.T) {
		res, tb := newTrackingResponse(http.StatusBadRequest, "")
		config := getBaseConfig()
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://api.snyk.io"})

		err := middleware.HandleResponse(res, config)
		assert.Error(t, err)
		assert.True(t, tb.closed, "original body must be closed even when empty")
	})
}

// --- test helpers ---

type trackingBody struct {
	io.ReadCloser
	closed bool
}

func (tb *trackingBody) Close() error {
	tb.closed = true
	return tb.ReadCloser.Close()
}

func newTrackingResponse(statusCode int, body string) (*http.Response, *trackingBody) {
	tb := &trackingBody{
		ReadCloser: io.NopCloser(strings.NewReader(body)),
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.snyk.io/test", nil)
	return &http.Response{
		StatusCode: statusCode,
		Body:       tb,
		Header:     http.Header{},
		Request:    req,
	}, tb
}

func buildRequest(url string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	req.Header.Set("snyk-request-id", "1234")
	if err != nil {
		panic(err)
	}

	return req
}

func getBaseConfig() configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	return config
}
