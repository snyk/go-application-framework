package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

//go:generate go tool github.com/golang/mock/mockgen -source=authenticator.go -destination ../mocks/authenticator.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/auth/

type Authenticator interface {
	// Authenticate authenticates the user and returns an error if the authentication failed.
	// Returns ErrAuthTimedOut if the underlying request times out.
	Authenticate() error
	// AddAuthenticationHeader adds the authentication header to the request.
	AddAuthenticationHeader(request *http.Request) error
	// IsSupported returns true if the authenticator is ready for use.
	// If false is returned, it is not possible to add authentication headers/env vars.
	IsSupported() bool
}

type CancelableAuthenticator interface {
	Authenticator
	// CancelableAuthenticate authenticates the user and returns an error if the authentication failed.
	// Takes a context that can be used to interrupt the authentication.
	// Returns ErrAuthCanceled when interrupted due to a context cancellation.
	// Returns ErrAuthTimedOut if the underlying request times out.
	CancelableAuthenticate(ctx context.Context) error
}

var (
	// ErrAuthCanceled is returned when an auth request is canceled by the calling context.
	ErrAuthCanceled = errors.New("authentication failed (canceled)")
	// ErrAuthTimedOut is returned when an auth request times out.
	ErrAuthTimedOut = errors.New("authentication failed (timeout)")
)

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
	return api.IsFedramp(endpoint)
}
