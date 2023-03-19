package auth

import (
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type Authenticator interface {
	// Authenticate authenticates the user and returns an error if the authentication failed.
	Authenticate() error
	// AddAuthenticationHeader adds the authentication header to the request.
	AddAuthenticationHeader(request *http.Request) error
	// AddEnvironmentVariables takes a slice of environment variables in a 'key=value' format (like the result of os.Environ),
	// and returns a slice with the authentication environment variables added to it.
	// If the headers are already set, an error is returned along with the original "env" slice.
	AddEnvironmentVariables(env []string) ([]string, error)
	// IsSupported returns true if the authenticator is ready for use.
	// If false is returned, it is not possible to add authentication headers/env vars.
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
