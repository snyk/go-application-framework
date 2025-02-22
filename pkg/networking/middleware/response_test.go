package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

		codes := []int{400, 401, 500}
		for _, code := range codes {
			snykErr := snyk_errors.Error{}
			url := fmt.Sprintf("%s/%d", server.URL, code)
			req := buildRequest(url)
			res, err := rt.RoundTrip(req)

			assert.Nil(t, res)
			assert.ErrorAs(t, err, &snykErr)
			assert.Equal(t, code, snykErr.StatusCode)

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

		assert.Nil(t, res)
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

		assert.Nil(t, res)
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

		assert.Nil(t, res)
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
