package auth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func Test_GetVerifier(t *testing.T) {
	expectedCount := 23
	verifier := createVerifier(expectedCount)
	actualCount := len(verifier)
	assert.Equal(t, expectedCount, actualCount)
}

func Test_getToken(t *testing.T) {
	expectedToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now(),
	}

	expectedTokenString, _ := json.Marshal(expectedToken)

	config := configuration.New()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(expectedTokenString))

	// method under test
	actualToken, err := getToken(config)

	assert.Nil(t, err)
	actualTokenString, _ := json.Marshal(actualToken)
	assert.Equal(t, expectedTokenString, actualTokenString)
}

func Test_getToken_notoken(t *testing.T) {
	config := configuration.New()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "")

	// method under test
	actualToken, err := getToken(config)

	assert.Nil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getToken_fails(t *testing.T) {
	config := configuration.New()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "something else")

	// method under test
	actualToken, err := getToken(config)

	assert.NotNil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getOAuthConfigration(t *testing.T) {
	webapp := "https://app.fedramp-alpha.snykgov.io"

	config := configuration.New()
	config.Set(configuration.WEB_APP_URL, webapp)

	oauthConfig := getOAuthConfiguration(config)

	assert.Equal(t, "", oauthConfig.RedirectURL)
	assert.Equal(t, OAUTH_CLIENT_ID, oauthConfig.ClientID)
	assert.Equal(t, webapp+"/oauth/authorize", oauthConfig.Endpoint.AuthURL)
	// assert.Equal(t, "https://id.fedramp-alpha.snykgov.io/oauth2/default/v1/token", oauthConfig.Endpoint.TokenURL)
}
