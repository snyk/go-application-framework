package middleware_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

func Test_ShouldRequireAuthentication(t *testing.T) {
	apiUrl, err := api.GetCanonicalApiUrlFromString("https://api.au.snyk.io")
	assert.NoError(t, err)

	cases := map[string]bool{
		"https://app.au.snyk.io":                 true,
		"https://app.snyk.io:443/something/else": false,
		"https://app.eu.snyk.io":                 false,
		"https://deeproxy.eu.snyk.io":            false,
		"https://example.com":                    false,
		"https://app.au.snyk.io.evil.com":        false,
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
		"https://somethingelse.com:443/":  true,
		"https://definitelynot.com/":      false,
		"https://anotherone.com":          true,
	}

	additionalSubdomains := []string{"deeproxy", "mydomain"}
	additionalUrls := []string{"https://somethingelse.com/", "https://anotherone.com:443/"}

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
