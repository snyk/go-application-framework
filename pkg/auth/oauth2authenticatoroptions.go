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

// WithApiURL sets an explicit API URL for the OAuth flow, bypassing the
// config's API_URL default function (which derives the URL from existing
// token audience claims). The app URL for the browser and post-auth redirect
// are derived automatically via api.DeriveAppUrl. Use this when the target
// endpoint differs from the currently saved/authenticated endpoint.
func WithApiURL(apiURL string) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.apiURL = apiURL
	}
}

// WithoutTokenPersistence prevents the authenticator from registering
// CONFIG_KEY_OAUTH_TOKEN for storage persistence. Use this for login-only
// authenticators where the consumer handles token persistence externally
// (e.g. after the user confirms a settings save). Without this option,
// persistToken writes the new token to the shared config file immediately,
// which can produce a mismatch if the user's auth method type was changed
// in the UI but not yet saved.
func WithoutTokenPersistence() OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.skipPersistInStorage = true
	}
}
