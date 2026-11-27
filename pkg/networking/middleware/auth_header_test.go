package middleware_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/machinecredential"
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
	const snykApi = "https://api.snyk.io"
	const euApi = "https://api.eu.snyk.io"

	additionalSubdomains := []string{"deeproxy", "mydomain"}
	additionalUrls := []string{"https://somethingelse.com/", "https://extension.example", "http://127.0.0.1:8080/code"}

	cases := []struct {
		name       string
		apiUrl     string
		requestUrl string
		want       bool
	}{
		{name: "EU subdomain mydomain with explicit default port", apiUrl: euApi, requestUrl: "https://mydomain.eu.snyk.io:443", want: true},
		{name: "EU host with another subdomain", apiUrl: euApi, requestUrl: "https://whatever.eu.snyk.io", want: false},
		{name: "EU subdomain deeproxy", apiUrl: euApi, requestUrl: "https://deeproxy.eu.snyk.io", want: true},
		{name: "additional URL with root path", apiUrl: euApi, requestUrl: "https://somethingelse.com/", want: true},
		{name: "unrelated host", apiUrl: euApi, requestUrl: "https://definitelynot.com/", want: false},
		{name: "EU app host", apiUrl: euApi, requestUrl: "https://app.eu.snyk.io/x", want: true},
		{name: "EU API host with a suffix appended", apiUrl: euApi, requestUrl: "https://api.eu.snyk.io.evil.example/", want: false},
		{name: "EU Snyk domain with a suffix appended", apiUrl: euApi, requestUrl: "https://eu.snyk.io.evil.example/", want: false},

		{name: "API host", apiUrl: snykApi, requestUrl: "https://api.snyk.io/rest/orgs", want: true},
		{name: "app host maps to API host", apiUrl: snykApi, requestUrl: "https://app.snyk.io/x", want: true},
		{name: "configured subdomain", apiUrl: snykApi, requestUrl: "https://deeproxy.snyk.io/x", want: true},
		{name: "upper-case host does not match, as before", apiUrl: snykApi, requestUrl: "https://API.SNYK.IO:443/x", want: false},
		{name: "bare Snyk domain", apiUrl: snykApi, requestUrl: "https://snyk.io/x", want: true},
		{name: "API URL without port matches any port", apiUrl: snykApi, requestUrl: "https://api.snyk.io:8443/x", want: true},
		{name: "API host with a trailing dot", apiUrl: snykApi, requestUrl: "https://api.snyk.io./x", want: true},
		{name: "bare Snyk domain with a trailing dot", apiUrl: snykApi, requestUrl: "https://snyk.io./x", want: true},
		{name: "API host with two trailing dots gets no token", apiUrl: snykApi, requestUrl: "https://api.snyk.io../x", want: false},
		{name: "ideographic full stop between labels does not match", apiUrl: snykApi, requestUrl: "https://api.snyk。io/x", want: false},
		{name: "ideographic trailing full stop does not match", apiUrl: snykApi, requestUrl: "https://api.snyk。/x", want: false},
		{name: "API host with two ideographic full stops gets no token", apiUrl: snykApi, requestUrl: "https://api.snyk。。/x", want: false},
		{name: "app host with a trailing dot", apiUrl: snykApi, requestUrl: "https://app.snyk.io./x", want: true},
		{name: "API host with a suffix appended", apiUrl: snykApi, requestUrl: "https://api.snyk.io.attacker.example/", want: false},
		{name: "API host with a partial label appended", apiUrl: snykApi, requestUrl: "https://api.snyk.iomalicious.example/", want: false},
		{name: "API host as userinfo of another host", apiUrl: snykApi, requestUrl: "https://api.snyk.io@evil.example/", want: false},
		{name: "API host and port as userinfo of another host", apiUrl: snykApi, requestUrl: "https://api.snyk.io:443@evil.example/", want: false},
		{name: "userinfo on the API host", apiUrl: snykApi, requestUrl: "https://user@api.snyk.io/", want: false},
		{name: "opaque URL naming the API host", apiUrl: snykApi, requestUrl: "https:api.snyk.io", want: false},
		{name: "bare Snyk domain with a suffix appended", apiUrl: snykApi, requestUrl: "https://snyk.io.attacker.example/", want: false},
		{name: "app host with a suffix appended", apiUrl: snykApi, requestUrl: "https://app.snyk.io.attacker.example/", want: false},
		{name: "subdomain with a suffix appended", apiUrl: snykApi, requestUrl: "https://deeproxy.snyk.io.attacker.example/", want: false},
		{name: "other scheme than the API URL", apiUrl: snykApi, requestUrl: "http://api.snyk.io/", want: false},
		{name: "non-ASCII host that lowercases to the API host does not match", apiUrl: snykApi, requestUrl: "https://apİ.snyk.io/", want: false},
		{name: "long s lookalike does not match", apiUrl: snykApi, requestUrl: "https://api.ſnyk.io/", want: false},
		{name: "fullwidth API label does not match", apiUrl: snykApi, requestUrl: "https://ａｐｉ.snyk.io/", want: false},
		{name: "non-ASCII host configured the same on both sides matches", apiUrl: "https://api.münchen.example", requestUrl: "https://api.münchen.example/x", want: true},

		{name: "dotted capital I host does not match the API host it lowercases to", apiUrl: "https://api.digital.com", requestUrl: "https://api.dİgital.com/", want: false},
		{name: "dotted capital I bare domain does not match the API host it lowercases to", apiUrl: "https://api.digital.com", requestUrl: "https://dİgital.com/", want: false},

		{name: "additional URL host with a suffix appended", apiUrl: snykApi, requestUrl: "https://extension.example.attacker.example/", want: false},
		{name: "additional URL without path matches any path", apiUrl: snykApi, requestUrl: "https://extension.example/anything", want: true},
		{name: "additional URL with port matches the same port", apiUrl: snykApi, requestUrl: "http://127.0.0.1:8080/code/x", want: true},
		{name: "additional URL with port rejects another port", apiUrl: snykApi, requestUrl: "http://127.0.0.1:9090/code/x", want: false},
		{name: "userinfo on an additional URL host", apiUrl: snykApi, requestUrl: "https://user@extension.example/", want: false},

		{name: "localhost API URL with the same port", apiUrl: "http://localhost:8080", requestUrl: "http://localhost:8080/x", want: true},
		{name: "IP API URL with the same port", apiUrl: "http://127.0.0.1:8080", requestUrl: "http://127.0.0.1:8080/x", want: true},
		{name: "IP API URL rejects another port", apiUrl: "http://127.0.0.1:8080", requestUrl: "http://127.0.0.1:9090/x", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requestUrl, err := url.Parse(tc.requestUrl)
			require.NoError(t, err)
			actual, err := middleware.ShouldRequireAuthentication(tc.apiUrl, requestUrl, additionalSubdomains, additionalUrls)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, actual)
		})
	}
}

func Test_ShouldRequireAuthentication_invalidApiUrlReturnsError(t *testing.T) {
	requestUrl, err := url.Parse("https://api.snyk.io/")
	require.NoError(t, err)

	matches, err := middleware.ShouldRequireAuthentication("http://[::1", requestUrl, nil, nil)
	assert.Error(t, err)
	assert.False(t, matches)
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
		// app.snyk.io canonicalizes to api.snyk.io, so ShouldRequireAuthentication returns true.
		cfg := newConfig(true)
		apiUrl := cfg.GetString(configuration.API_URL)
		reqUrl, err := url.Parse("https://app.snyk.io/rest/endpoint")
		assert.NoError(t, err)
		requiresAuth, err := middleware.ShouldRequireAuthentication(apiUrl, reqUrl, nil, nil)
		assert.NoError(t, err)
		assert.True(t, requiresAuth, "app.snyk.io must require auth for the 401 gate to fire")

		called := false
		next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK}, nil
		})
		ctrl := gomock.NewController(t)
		auth := mocks.NewMockAuthenticator(ctrl)
		auth.EXPECT().AddAuthenticationHeader(gomock.Any()).Return(nil).Times(1)

		m := middleware.NewAuthHeaderMiddlewareWithLogger(cfg, auth, next, &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://app.snyk.io/rest/endpoint"))
		assert.Error(t, err)
		var snykErr snyk_errors.Error
		assert.ErrorAs(t, err, &snykErr, "expected UnauthorisedError from error catalog")
		assert.NotNil(t, resp, "response must be non-nil so callers can read StatusCode")
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

func TestAuthHeaderMiddleware_MachineAuthenticationError(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.New()
	config.Set(configuration.API_URL, "https://api.snyk.io")

	newRequest := func(t *testing.T, rawURL string) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, rawURL, http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "token caller-set")
		req.Header.Set("Session-Token", "token caller-set")
		return req
	}

	type sent struct {
		called        bool
		authorization string
		sessionToken  string
	}
	recordingNext := func(s *sent) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			s.called = true
			s.authorization = r.Header.Get("Authorization")
			s.sessionToken = r.Header.Get("Session-Token")
			return &http.Response{StatusCode: http.StatusOK}, nil
		})
	}

	t.Run("Snyk API host — blocks the request, whatever the caller set, and returns the cause", func(t *testing.T) {
		var s sent
		authenticator := mocks.NewMockAuthenticator(gomock.NewController(t))
		authenticator.EXPECT().AddAuthenticationHeader(gomock.Any()).
			Return(&machinecredential.AuthenticationError{Err: errors.New("the stored machine credential cannot be used")})

		m := middleware.NewAuthHeaderMiddlewareWithLogger(config, authenticator, recordingNext(&s), &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://app.snyk.io/rest/endpoint"))

		var machineErr *machinecredential.AuthenticationError
		require.ErrorAs(t, err, &machineErr)
		assert.ErrorContains(t, err, "the stored machine credential cannot be used")
		assert.False(t, s.called, "the request is not sent")
		require.NotNil(t, resp, "a nil response makes a proxying caller relay the original request itself")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.NotNil(t, resp.Header)
		assert.NotNil(t, resp.Request)
	})

	t.Run("other authentication error — passes through with the caller's headers", func(t *testing.T) {
		var s sent
		authenticator := mocks.NewMockAuthenticator(gomock.NewController(t))
		authenticator.EXPECT().AddAuthenticationHeader(gomock.Any()).Return(errors.New("refresh failed"))

		m := middleware.NewAuthHeaderMiddlewareWithLogger(config, authenticator, recordingNext(&s), &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://app.snyk.io/rest/endpoint"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, s.called)
		assert.Equal(t, "token caller-set", s.authorization)
		assert.Equal(t, "token caller-set", s.sessionToken)
	})

	t.Run("host without Snyk authentication — keeps the caller's headers", func(t *testing.T) {
		var s sent
		authenticator := mocks.NewMockAuthenticator(gomock.NewController(t))
		authenticator.EXPECT().AddAuthenticationHeader(gomock.Any()).
			Return(&machinecredential.AuthenticationError{Err: errors.New("unused")}).Times(0)

		m := middleware.NewAuthHeaderMiddlewareWithLogger(config, authenticator, recordingNext(&s), &logger)
		resp, err := m.RoundTrip(newRequest(t, "https://example.com/api/something"))

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, s.called)
		assert.Equal(t, "token caller-set", s.authorization)
		assert.Equal(t, "token caller-set", s.sessionToken)
	})
}

func TestAuthHeaderMiddleware_TokenOnlySentToConfiguredOrigin(t *testing.T) {
	const token = "token test-token"

	cases := []struct {
		name                     string
		requestUrl               string
		authenticatorIssuesToken bool
		wantBlocked              bool
		wantAuthorization        string
	}{
		{name: "allowed API host gets the token", requestUrl: "https://api.snyk.io/rest/orgs", authenticatorIssuesToken: true, wantAuthorization: token},
		{name: "API host with a suffix appended gets no token and is not blocked", requestUrl: "https://api.snyk.io.attacker.example/", authenticatorIssuesToken: true},
		{name: "allowed API host without a token is blocked", requestUrl: "https://api.snyk.io/rest/orgs", authenticatorIssuesToken: false, wantBlocked: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			authenticator := mocks.NewMockAuthenticator(ctrl)
			authenticator.EXPECT().AddAuthenticationHeader(gomock.Any()).DoAndReturn(func(r *http.Request) error {
				if tc.authenticatorIssuesToken {
					r.Header.Set("Authorization", token)
				}
				return nil
			}).AnyTimes()

			config := configuration.New()
			config.Set(configuration.API_URL, "https://api.snyk.io")
			config.Set(configuration.AUTHENTICATION_SUBDOMAINS, []string{"deeproxy"})
			config.Set(configuration.STOP_REQUESTS_WITHOUT_AUTH, true)

			var sentAuthorization string
			next := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				sentAuthorization = r.Header.Get("Authorization")
				return &http.Response{StatusCode: http.StatusOK}, nil
			})

			req, err := http.NewRequest(http.MethodGet, tc.requestUrl, http.NoBody)
			require.NoError(t, err)

			resp, err := middleware.NewAuthHeaderMiddleware(config, authenticator, next).RoundTrip(req)
			if tc.wantBlocked {
				assert.Error(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.wantAuthorization, sentAuthorization)
		})
	}
}

func Test_ShouldRequireAuthentication_emptyApiUrlUsesDefaultApi(t *testing.T) {
	cases := []struct {
		name       string
		requestUrl string
		want       bool
	}{
		{name: "default API host gets the token", requestUrl: "https://api.snyk.io/", want: true},
		{name: "other host does not get the token", requestUrl: "https://attacker.example/", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requestUrl, err := url.Parse(tc.requestUrl)
			require.NoError(t, err)
			actual, err := middleware.ShouldRequireAuthentication("", requestUrl, nil, nil)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, actual)
		})
	}
}
