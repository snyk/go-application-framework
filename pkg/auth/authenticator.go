package auth

import (
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type Authenticator interface {
	Authenticate() error
	AddAuthenticationHeader(request *http.Request) error
	IsSupported() bool
}

func CreateAuthenticator(config configuration.Configuration, httpClient *http.Client) Authenticator {
	var authenticator Authenticator

	// try oauth authenticator
	tmpAuthenticator := NewOAuth2Authenticator(config, httpClient)
	if tmpAuthenticator.IsSupported() {
		authenticator = tmpAuthenticator
	}

	// create token authenticator
	if authenticator == nil {
		authenticator = NewTokenAuthenticator(func() string { return GetAuthHeader(config) })
	}

	return authenticator
}
