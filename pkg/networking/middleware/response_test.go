package middleware_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/stretchr/testify/assert"
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
		case "/jsonapi":
			w.WriteHeader(http.StatusProxyAuthRequired)
			_, err := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"errors":[{"status":"407","detail":"Proxy auth required"}]}`))
			assert.Nil(t, err)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	rt := middleware.NewReponseMiddleware(http.DefaultTransport, nil)

	t.Run("no error for 2xx", func(t *testing.T) {
		req := buildRequest(server.URL)
		_, err := rt.RoundTrip(req)

		assert.Nil(t, err)
	})

	t.Run("proper errors for matching status codes", func(t *testing.T) {
		codes := []int{400, 401, 500}
		for _, code := range codes {
			snykErr := snyk_errors.Error{}
			url := fmt.Sprintf("%s/%d", server.URL, code)
			req := buildRequest(url)
			res, err := rt.RoundTrip(req)

			assert.Nil(t, res)
			assert.ErrorAs(t, err, &snykErr)
			assert.Equal(t, code, snykErr.StatusCode)
		}
	})

	t.Run("no error if no status code matches", func(t *testing.T) {
		req := buildRequest(server.URL + "/404")
		_, err := rt.RoundTrip(req)

		assert.Nil(t, err)
	})
}

func Test_ResponseMiddleware_WithErrorHandler(t *testing.T) {
	expectedErr := errors.New("Big oopsie in the middleware")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	rt := middleware.NewReponseMiddleware(http.DefaultTransport, func(err error, ctx context.Context) error {
		return expectedErr // this will override error parameter
	})

	req := buildRequest(server.URL)
	res, err := rt.RoundTrip(req)
	assert.Nil(t, res)
	assert.ErrorAs(t, err, &expectedErr)
}

func buildRequest(url string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		panic(err)
	}

	return req
}
