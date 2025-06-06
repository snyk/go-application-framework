package auth

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type OAuth2AuthenticatorOption func(authenticator *oAuth2Authenticator)

func WithOpenBrowserFunc(openBrowserFunc func(string)) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.openBrowserFunc = openBrowserFunc
	}
}

// WithShutdownServerFunc sets the function that is called on server shutdown.
// shutdownServerFunc must be/call a function which is race condition safe with server.Server if it is called first
// and will result in server.Server exiting immediately when called.
func WithShutdownServerFunc(shutdownServerFunc func(server *http.Server)) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.shutdownServerFunc = shutdownServerFunc
	}
}

func WithLogger(logger *zerolog.Logger) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.logger = logger
	}
}

func WithTokenRefresherFunc(refreshFunc func(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error)) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.tokenRefresherFunc = refreshFunc
	}
}

func WithHttpClient(httpClient *http.Client) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.httpClient = httpClient
	}
}
