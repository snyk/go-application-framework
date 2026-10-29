package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
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
	// ErrMachineNotEnrolled is returned by StoredMachineCredential when no machine credential is stored.
	ErrMachineNotEnrolled = machinecredential.ErrNotEnrolled
)

// StoredMachineCredential returns the stored machine credential: its client id and its private key as
// PKCS#8 PEM, the form `snyk auth --client-secret` accepts.
func StoredMachineCredential(config configuration.Configuration) (clientID, keyPEM string, err error) {
	credential, err := machinecredential.Load(config)
	if err != nil {
		return "", "", err
	}
	pemBytes, err := machineenrollment.EncodeKeyPEM(credential.Key)
	if err != nil {
		return "", "", err
	}
	return credential.ClientID, string(pemBytes), nil
}

func CreateAuthenticator(config configuration.Configuration, httpClient *http.Client) Authenticator {
	var authenticator Authenticator

	// try oauth authenticator
	tmpAuthenticator, err := newOAuth2AuthenticatorForStoredCredential(config, httpClient)
	if err != nil {
		return &failingAuthenticator{err: err}
	}
	if tmpAuthenticator.IsSupported() {
		authenticator = tmpAuthenticator
	}

	// create token authenticator
	if authenticator == nil {
		authenticator = NewTokenAuthenticator(func() string { return GetAuthHeader(config) })
	}

	return authenticator
}

// newOAuth2AuthenticatorForStoredCredential lets an enrolled machine re-mint its access token from the
// stored key. A stored credential that cannot be read is an error rather than a reason to fall back.
func newOAuth2AuthenticatorForStoredCredential(config configuration.Configuration, httpClient *http.Client) (Authenticator, error) {
	opts := []OAuth2AuthenticatorOption{WithHttpClient(httpClient)}
	credential, err := machinecredential.Load(config)
	switch {
	case err == nil:
		opts = append(opts, WithClientAssertionProvider(credential.ClientID, machinecredential.NewSigner(credential.Key)))
	case !errors.Is(err, machinecredential.ErrNotEnrolled):
		return nil, &machinecredential.AuthenticationError{Err: fmt.Errorf("machine authentication failed, the stored machine credential cannot be used: %w", err)}
	}
	return NewOAuth2AuthenticatorWithOpts(config, opts...), nil
}

type failingAuthenticator struct {
	err error
}

func (f *failingAuthenticator) Authenticate() error { return f.err }

func (f *failingAuthenticator) AddAuthenticationHeader(*http.Request) error { return f.err }

func (f *failingAuthenticator) IsSupported() bool { return true }

func IsKnownOAuthEndpoint(endpoint string) bool {
	return api.IsFedramp(endpoint)
}
