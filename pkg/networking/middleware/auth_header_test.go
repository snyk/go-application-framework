package middleware_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func Test_ShouldRequireAuthentication(t *testing.T) {
	apiUrl, err := api.GetCanonicalApiUrlFromString("https://api.au.snyk.io")
	assert.NoError(t, err)

	cases := map[string]bool{
		"https://app.au.snyk.io":                 true,
		"https://app.snyk.io:443/something/else": false,
		"https://app.eu.snyk.io":                 false,
		"https://deeproxy.eu.snyk.io":            false,
		"https://example.com":                    false,
	}

	additionalSubdomains := []string{}

	for u, expected := range cases {
		requestUrl, err := url.Parse(u)
		assert.NoError(t, err)
		actual, err := middleware.ShouldRequireAuthentication(apiUrl, requestUrl, additionalSubdomains, additionalSubdomains)
		assert.Nil(t, err)
		assert.Equal(t, expected, actual)
	}
}

func Test_ShouldRequireAuthentication_subdomains(t *testing.T) {
	apiUrl, err := api.GetCanonicalApiUrlFromString("https://api.eu.snyk.io")
	assert.NoError(t, err)

	cases := map[string]bool{
		"https://mydomain.eu.snyk.io:443": true,
		"https://whatever.eu.snyk.io":     false,
		"https://deeproxy.eu.snyk.io":     true,
		"https://somethingelse.com/":      true,
		"https://definitelynot.com/":      false,
	}

	additionalSubdomains := []string{"deeproxy", "mydomain"}
	additionalUrls := []string{"https://somethingelse.com/"}

	for u, expected := range cases {
		t.Run(u, func(t *testing.T) {
			requestUrl, err := url.Parse(u)
			assert.NoError(t, err)
			actual, err := middleware.ShouldRequireAuthentication(apiUrl, requestUrl, additionalSubdomains, additionalUrls)
			assert.Nil(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func Test_AddAuthenticationHeader(t *testing.T) {
	ctrl := gomock.NewController(t)
	authenticator := mocks.NewMockAuthenticator(ctrl)
	config := configuration.New()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.AUTHENTICATION_SUBDOMAINS, []string{"deeproxy"})

	// case: headers added (api)
	url, err := url.Parse("https://app.snyk.io/rest/endpoint1")
	assert.NoError(t, err)
	request := &http.Request{
		URL: url,
	}

	authenticator.EXPECT().AddAuthenticationHeader(request).Times(1)

	err = middleware.AddAuthenticationHeader(authenticator, config, request)
	assert.NoError(t, err)

	// case: headers added (deeproxy)
	url2, err := url.Parse("https://deeproxy.snyk.io/rest/endpoint23")
	assert.NoError(t, err)
	request2 := &http.Request{
		URL: url2,
	}

	authenticator.EXPECT().AddAuthenticationHeader(request2).Times(1)

	err = middleware.AddAuthenticationHeader(authenticator, config, request2)
	assert.NoError(t, err)

	// case: no headers added
	url3, err := url.Parse("https://app.au.snyk.io/rest/endpoint1")
	assert.NoError(t, err)
	request3 := &http.Request{
		URL: url3,
	}

	err = middleware.AddAuthenticationHeader(authenticator, config, request3)
	assert.NoError(t, err)
}

func TestAuthHeaderMiddleware_StopRequestsWithoutAuth(t *testing.T) {
	logger := zerolog.Nop()

	newConfig := func(stopEnabled bool) configuration.Configuration {
		cfg := configuration.New()
		cfg.Set(configuration.API_URL, "https://api.snyk.io")
		cfg.Set(configuration.STOP_REQUESTS_WITHOUT_AUTH, stopEnabled)
		return cfg
	}

	newRequest := func(t *testing.T, rawURL string) *http.Request {
		t.Helper()
		u, err := url.Parse(rawURL)
		assert.NoError(t, err)
		return &http.Request{URL: u, Header: make(http.Header)}
	}

	t.Run("flag off — passthrough even without token", func(t *testing.T) {
		called := false
		next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK}, nil
		})
		ctrl := gomock.NewController(t)
		auth := mocks.NewMockAuthenticator(ctrl)
		auth.EXPECT().AddAuthenticationHeader(gomock.Any()).Return(nil).Times(1)

		m := middleware.NewAuthHeaderMiddlewareWithLogger(newConfig(false), auth, next, &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://app.snyk.io/rest/endpoint"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, called)
	})

	t.Run("flag on, no token, Snyk API URL — returns 401 without calling next", func(t *testing.T) {
		called := false
		next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK}, nil
		})
		ctrl := gomock.NewController(t)
		auth := mocks.NewMockAuthenticator(ctrl)
		auth.EXPECT().AddAuthenticationHeader(gomock.Any()).Return(nil).Times(1)

		m := middleware.NewAuthHeaderMiddlewareWithLogger(newConfig(true), auth, next, &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://app.snyk.io/rest/endpoint"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.False(t, called)
	})

	t.Run("flag on, token present — passthrough", func(t *testing.T) {
		called := false
		next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK}, nil
		})
		ctrl := gomock.NewController(t)
		auth := mocks.NewMockAuthenticator(ctrl)
		auth.EXPECT().AddAuthenticationHeader(gomock.Any()).DoAndReturn(func(r *http.Request) error {
			r.Header.Set("Authorization", "token abc123")
			return nil
		}).Times(1)

		m := middleware.NewAuthHeaderMiddlewareWithLogger(newConfig(true), auth, next, &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://app.snyk.io/rest/endpoint"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, called)
	})

	t.Run("flag on, no token, non-Snyk URL — passthrough", func(t *testing.T) {
		called := false
		next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK}, nil
		})
		ctrl := gomock.NewController(t)
		auth := mocks.NewMockAuthenticator(ctrl)
		auth.EXPECT().AddAuthenticationHeader(gomock.Any()).Times(0)

		m := middleware.NewAuthHeaderMiddlewareWithLogger(newConfig(true), auth, next, &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://example.com/api/something"))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, called)
	})
}

func TestAuthenticationError_Is(t *testing.T) {
	ctrl := gomock.NewController(t)
	config := configuration.New()
	config.Set(configuration.API_URL, "https://api.snyk.io")

	url, err := url.Parse("https://app.snyk.io/rest/endpoint1")
	assert.NoError(t, err)
	request := &http.Request{
		URL: url,
	}

	authenticator := mocks.NewMockAuthenticator(ctrl)
	authenticator.EXPECT().AddAuthenticationHeader(gomock.Any()).Return(fmt.Errorf("nope"))
	err = middleware.AddAuthenticationHeader(authenticator, config, request)
	assert.ErrorIs(t, err, middleware.ErrAuthenticationFailed)
	assert.ErrorContains(t, err, "nope")
}
