package auth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

//go:generate $GOPATH/bin/mockgen -source=authenticator.go -destination ../mocks/authenticator.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/auth/

type Authenticator interface {
	// Authenticate authenticates the user and returns an error if the authentication failed.
	Authenticate() error
	// AddAuthenticationHeader adds the authentication header to the request.
	AddAuthenticationHeader(request *http.Request) error
	// IsSupported returns true if the authenticator is ready for use.
	// If false is returned, it is not possible to add authentication headers/env vars.
	IsSupported() bool
}

func CreateAuthenticator(config configuration.Configuration, httpClient *http.Client) Authenticator {
	var authenticator Authenticator

	// try oauth authenticator
	tmpAuthenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(httpClient))
	if tmpAuthenticator.IsSupported() {
		authenticator = tmpAuthenticator
	}

	// create token authenticator
	if authenticator == nil {
		authenticator = NewTokenAuthenticator(func() string { return GetAuthHeader(config) })
	}

	return authenticator
}

func IsKnownOAuthEndpoint(endpoint string) bool {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	hostname := parsedURL.Hostname()
	return strings.HasSuffix(hostname, "snykgov.io")
}
