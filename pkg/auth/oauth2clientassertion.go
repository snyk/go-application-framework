package auth

import "context"

// ClientAssertionProvider supplies a private_key_jwt-style client assertion (RFC 7523) for the
// OAuth2 client_credentials grant, decoupling the authenticator from any specific key-management or
// enrollment scheme.
type ClientAssertionProvider interface {
	// ClientAssertion returns the client_assertion_type and a freshly signed client_assertion for a
	// token request to tokenURL, authenticating as clientID. Implementations should mint a new
	// assertion on every call; authorization servers are expected to accept each one only once.
	ClientAssertion(ctx context.Context, clientID, tokenURL string) (assertionType, assertion string, err error)
}

// WithClientAssertionProvider configures the authenticator to use the client_credentials grant with
// a client assertion minted by p, authenticating as clientID, instead of a static client secret.
func WithClientAssertionProvider(clientID string, p ClientAssertionProvider) OAuth2AuthenticatorOption {
	return func(authenticator *oAuth2Authenticator) {
		authenticator.assertionClientID = clientID
		authenticator.assertionProvider = p
		authenticator.grantType = ClientCredentialsGrant
		authenticator.tokenRefresherFunc = authenticator.refreshTokenClientAssertion
	}
}
