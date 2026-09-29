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

// CreateAuthenticatorOption customizes CreateAuthenticator.
type CreateAuthenticatorOption func(*createAuthenticatorOptions)

type createAuthenticatorOptions struct {
	machineSource MachineIdentitySource
}

// WithMachineIdentitySource makes a machine identity available for selection. It is only used
// when the identity mode resolves to machine.
func WithMachineIdentitySource(source MachineIdentitySource) CreateAuthenticatorOption {
	return func(o *createAuthenticatorOptions) {
		o.machineSource = source
	}
}

// CreateAuthenticator returns the authenticator for the identity mode found in configuration.
func CreateAuthenticator(config configuration.Configuration, httpClient *http.Client, opts ...CreateAuthenticatorOption) Authenticator {
	return CreateAuthenticatorForMode(IdentityModeFromConfiguration(config), config, httpClient, opts...)
}

// CreateAuthenticatorForMode returns the authenticator for an explicit identity mode, which lets a
// caller pick the machine or the user identity for a single request regardless of configuration.
func CreateAuthenticatorForMode(mode IdentityMode, config configuration.Configuration, httpClient *http.Client, opts ...CreateAuthenticatorOption) Authenticator {
	var authenticator Authenticator

	options := createAuthenticatorOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	// machine identity never falls back to user credentials, a missing source is an explicit failure
	if mode == IdentityModeMachine {
		return NewMachineIdentityAuthenticator(options.machineSource)
	}

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
