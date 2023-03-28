package middleware_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/stretchr/testify/assert"
)

func Test_ShouldRequireAuthentication(t *testing.T) {
	apiUrl, _ := api.GetCanonicalApiUrlFromString("https://api.au.snyk.io")

	cases := map[string]bool{
		"https://app.au.snyk.io":                 true,
		"https://app.snyk.io:443/something/else": false,
		"https://app.eu.snyk.io":                 false,
		"https://deeproxy.eu.snyk.io":            false,
		"https://example.com":                    false,
	}

	additionalSubdomains := []string{}

	for u, expected := range cases {
		requestUrl, _ := url.Parse(u)
		actual, err := middleware.ShouldRequireAuthentication(apiUrl, requestUrl, additionalSubdomains)
		assert.Nil(t, err)
		assert.Equal(t, expected, actual)
	}

}

func Test_ShouldRequireAuthentication_subdomains(t *testing.T) {
	apiUrl, _ := api.GetCanonicalApiUrlFromString("https://api.eu.snyk.io")

	cases := map[string]bool{
		"https://mydomain.eu.snyk.io:443": true,
		"https://whatever.eu.snyk.io":     false,
		"https://deeproxy.eu.snyk.io":     true,
	}

	additionalSubdomains := []string{"deeproxy", "mydomain"}

	for u, expected := range cases {
		t.Run(u, func(t *testing.T) {
			requestUrl, _ := url.Parse(u)
			actual, err := middleware.ShouldRequireAuthentication(apiUrl, requestUrl, additionalSubdomains)
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
	url, _ := url.Parse("https://app.snyk.io/rest/endpoint1")
	request := &http.Request{
		URL: url,
	}

	authenticator.EXPECT().AddAuthenticationHeader(request).Times(1)

	err := middleware.AddAuthenticationHeader(authenticator, config, request)
	assert.Nil(t, err)

	// case: headers added (deeproxy)
	url2, _ := url.Parse("https://deeproxy.snyk.io/rest/endpoint23")
	request2 := &http.Request{
		URL: url2,
	}

	authenticator.EXPECT().AddAuthenticationHeader(request2).Times(1)

	err = middleware.AddAuthenticationHeader(authenticator, config, request2)
	assert.Nil(t, err)

	// case: no headers added
	url3, _ := url.Parse("https://app.au.snyk.io/rest/endpoint1")
	request3 := &http.Request{
		URL: url3,
	}

	err = middleware.AddAuthenticationHeader(authenticator, config, request3)
	assert.Nil(t, err)

}
