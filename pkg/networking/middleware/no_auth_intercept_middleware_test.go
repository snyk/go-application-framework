package middleware_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func makeRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &http.Request{URL: u, Header: make(http.Header)}
}

func newTestMiddleware(t *testing.T, stopEnabled bool, next http.RoundTripper) *middleware.NoAuthInterceptMiddleware {
	t.Helper()
	cfg := configuration.New()
	cfg.Set(configuration.API_URL, "https://api.snyk.io")
	cfg.Set(configuration.STOP_REQUESTS_WITHOUT_AUTH, stopEnabled)
	logger := zerolog.Nop()
	return middleware.NewNoAuthInterceptMiddleware(cfg, &logger, next)
}

func Test_NoAuthIntercept_FlagOff_Passthrough(t *testing.T) {
	called := false
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK}, nil
	})

	m := newTestMiddleware(t, false, next)
	req := makeRequest(t, "https://app.snyk.io/rest/endpoint")

	resp, err := m.RoundTrip(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, called)
}

func Test_NoAuthIntercept_FlagOn_NoToken_Returns401(t *testing.T) {
	called := false
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK}, nil
	})

	m := newTestMiddleware(t, true, next)
	req := makeRequest(t, "https://app.snyk.io/rest/endpoint")
	// no Authorization header set

	resp, err := m.RoundTrip(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.False(t, called)
}

func Test_NoAuthIntercept_FlagOn_TokenPresent_Passthrough(t *testing.T) {
	called := false
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK}, nil
	})

	m := newTestMiddleware(t, true, next)
	req := makeRequest(t, "https://app.snyk.io/rest/endpoint")
	req.Header.Set("Authorization", "token some-api-token")

	resp, err := m.RoundTrip(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, called)
}

func Test_NoAuthIntercept_FlagOn_NonAuthURL_Passthrough(t *testing.T) {
	called := false
	next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK}, nil
	})

	m := newTestMiddleware(t, true, next)
	req := makeRequest(t, "https://example.com/api/something")
	// no Authorization header — but URL doesn't require auth

	resp, err := m.RoundTrip(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, called)
}
