package auth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

type OAuth2AuthenticatorOption func(authenticator *oAuth2Authenticator)

func WithOpenBrowserFunc(openBrowserFunc func(string)) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.openBrowserFunc = openBrowserFunc
	}
}

func WithShutdownServerFunc(shutdownServerFunc func(server *http.Server)) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.shutdownServerFunc = shutdownServerFunc
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
