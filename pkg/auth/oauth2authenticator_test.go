package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	actualToken, err := GetOAuthToken(config)

	assert.Nil(t, err)
	actualTokenString, _ := json.Marshal(actualToken)
	assert.Equal(t, expectedTokenString, actualTokenString)
}

func Test_getToken_NoToken_ReturnsNil(t *testing.T) {
	config := configuration.New()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "")

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.Nil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getToken_BadToken_ReturnsError(t *testing.T) {
	config := configuration.New()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "something else")

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.NotNil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getOAuthConfiguration(t *testing.T) {
	webapp := "https://app.fedramp-alpha.snykgov.io"

	config := configuration.New()
	config.Set(configuration.WEB_APP_URL, webapp)

	oauthConfig := getOAuthConfiguration(config)

	assert.Equal(t, "", oauthConfig.RedirectURL)
	assert.Equal(t, OAUTH_CLIENT_ID, oauthConfig.ClientID)
	assert.Equal(t, webapp+"/oauth/authorize", oauthConfig.Endpoint.AuthURL)
	// assert.Equal(t, "https://id.fedramp-alpha.snykgov.io/oauth2/default/v1/token", oauthConfig.Endpoint.TokenURL)
}

func Test_AddEnvironmentVariables_ValidToken_AddsAccessToken(t *testing.T) {
	config, token := createConfigWithValidToken()

	authenticator := NewOAuth2Authenticator(config, http.DefaultClient)
	preExistingEnvVar := "someKey=someValue"
	env := []string{preExistingEnvVar}
	env, err := authenticator.AddEnvironmentVariables(env)

	t.Run("no error", func(t *testing.T) {
		assert.Nil(t, err)
	})
	t.Run("adds access token", func(t *testing.T) {
		assert.Contains(t, env, fmt.Sprint("SNYK_OAUTH_TOKEN=", token.AccessToken))
	})
	t.Run("doesn't remove existing env vars", func(t *testing.T) {
		assert.Contains(t, env, preExistingEnvVar)
	})
}

func Test_AddEnvironmentVariables_HeadersAlreadySet_ReturnsErrorAndSameEnv(t *testing.T) {
	config, _ := createConfigWithValidToken()
	authenticator := NewOAuth2Authenticator(config, http.DefaultClient)
	expectedEnv := []string{"SNYK_OAUTH_TOKEN=SomeOtherToken"}

	resultEnv, err := authenticator.AddEnvironmentVariables(expectedEnv)

	assert.NotNil(t, expectedEnv)
	assert.NotNil(t, err)
	assert.Len(t, resultEnv, 1)
	assert.Equal(t, expectedEnv, resultEnv)
}

func createConfigWithValidToken() (configuration.Configuration, oauth2.Token) {
	config := configuration.New()
	token := createValidToken()
	tokenBytes, _ := json.Marshal(token)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))
	return config, token
}

func createValidToken() oauth2.Token {
	return oauth2.Token{
		AccessToken:  "1234",
		TokenType:    "bearer",
		RefreshToken: "4321",
		Expiry:       time.Now().Add(24 * time.Hour),
	}
}
