package auth

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func getTestOauthTokenStorageType(t *testing.T) string {
	t.Helper()
	expectedToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now(),
	}

	expectedTokenString, err := json.Marshal(expectedToken)
	assert.NoError(t, err)
	return string(expectedTokenString)
}

func Test_CreateAuthenticator_token(t *testing.T) {
	config := configuration.NewFromFiles("")
	authenticator := CreateAuthenticator(config, http.DefaultClient)
	_, ok := authenticator.(*tokenAuthenticator)
	assert.True(t, ok)
}

func Test_CreateAuthenticator_token_oauthDisabled(t *testing.T) {
	config := configuration.NewFromFiles("")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, getTestOauthTokenStorageType(t))
	config.Set(configuration.AUTHENTICATION_TOKEN, "api token")
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	_, ok := authenticator.(*tokenAuthenticator)
	assert.True(t, ok)
}

func Test_CreateAuthenticator_oauth_oauthEnabled(t *testing.T) {
	config := configuration.NewFromFiles("")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, getTestOauthTokenStorageType(t))
	config.Set(configuration.AUTHENTICATION_TOKEN, "api token")
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	_, ok := authenticator.(*oAuth2Authenticator)
	assert.True(t, ok)
}

func Test_IsKnownOAuthEndpoint(t *testing.T) {
	assert.True(t, IsKnownOAuthEndpoint("https://snykgov.io"))
	assert.True(t, IsKnownOAuthEndpoint("https://snykgov.io/"))
	assert.True(t, IsKnownOAuthEndpoint("https://snykgov.io/some/path/"))
	assert.True(t, IsKnownOAuthEndpoint("https://www.snykgov.io/"))
	assert.False(t, IsKnownOAuthEndpoint("https://snyk.io"))
	assert.False(t, IsKnownOAuthEndpoint("https://snyk.io/"))
	assert.False(t, IsKnownOAuthEndpoint("https://snyk.io/"))
}
