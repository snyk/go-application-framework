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

func getTestOauthTokenStorageType() string {
	expectedToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now(),
	}

	expectedTokenString, _ := json.Marshal(expectedToken)
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
	config.Set(CONFIG_KEY_OAUTH_TOKEN, getTestOauthTokenStorageType())
	config.Set(configuration.AUTHENTICATION_TOKEN, "api token")
	config.Set(configuration.OAUTH_AUTH_ENABLED, false)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	_, ok := authenticator.(*tokenAuthenticator)
	assert.True(t, ok)
}

func Test_CreateAuthenticator_oauth_oauthEnabled(t *testing.T) {
	config := configuration.NewFromFiles("")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, getTestOauthTokenStorageType())
	config.Set(configuration.AUTHENTICATION_TOKEN, "api token")
	config.Set(configuration.OAUTH_AUTH_ENABLED, true)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	_, ok := authenticator.(*oAuth2Authenticator)
	assert.True(t, ok)
}
