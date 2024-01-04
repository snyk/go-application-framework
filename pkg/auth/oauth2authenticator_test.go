package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_GetVerifier(t *testing.T) {
	expectedCount := 23
	verifier, err := createVerifier(expectedCount)
	assert.NoError(t, err)
	actualCount := len(verifier)
	assert.Equal(t, expectedCount, actualCount)
}

func Test_randIndex(t *testing.T) {
	tests := map[string]struct {
		limit int
		err   string
	}{
		"limit negative fails": {
			limit: -1,
			err:   "invalid limit -1",
		},
		"limit zero fails": {
			err: "invalid limit 0",
		},
		"limit one ok": {
			limit: 1,
		},
		"other limit ok": {
			limit: 213,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			index, err := randIndex(test.limit)
			if test.err != "" {
				assert.ErrorContains(t, err, test.err)
			} else {
				assert.Conditionf(t, func() (success bool) { return index >= 0 && index < test.limit }, "index %d within range", index)
			}
		})
	}
}

func Test_getToken(t *testing.T) {
	expectedToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now(),
	}

	expectedTokenString, _ := json.Marshal(expectedToken)

	config := configuration.NewInMemory()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(expectedTokenString))

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.Nil(t, err)
	actualTokenString, _ := json.Marshal(actualToken)
	assert.Equal(t, expectedTokenString, actualTokenString)
}

func Test_getToken_NoToken_ReturnsNil(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "")

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.Nil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getToken_BadToken_ReturnsError(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "something else")

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.NotNil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getOAuthConfiguration(t *testing.T) {
	webapp := "https://app.fedramp-alpha.snykgov.io"
	api := "https://api.fedramp-alpha.snykgov.io"

	config := configuration.NewInMemory()
	config.Set(configuration.WEB_APP_URL, webapp)
	config.Set(configuration.API_URL, api)

	oauthConfig := getOAuthConfiguration(config)

	assert.Equal(t, "", oauthConfig.RedirectURL)
	assert.Equal(t, OAUTH_CLIENT_ID, oauthConfig.ClientID)
	assert.Equal(t, webapp+"/oauth2/authorize", oauthConfig.Endpoint.AuthURL)
	assert.Equal(t, api+"/oauth2/token", oauthConfig.Endpoint.TokenURL)
}

func Test_AddAuthenticationHeader_validToken(t *testing.T) {
	// prepare test
	newToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now().Add(60 * time.Second).UTC(),
	}

	config := configuration.NewInMemory()
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	authenticator.(*oAuth2Authenticator).persistToken(newToken)
	authenticator.(*oAuth2Authenticator).tokenRefresherFunc = func(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
		assert.False(t, true, "The token is valid and no refresh is required!")
		return newToken, nil
	}

	emptyRequest := &http.Request{
		Header: http.Header{},
	}

	// run method under test
	err := authenticator.AddAuthenticationHeader(emptyRequest)
	assert.Nil(t, err)

	// compare
	expectedAuthHeader := "Bearer " + newToken.AccessToken
	actualAuthHeader := emptyRequest.Header.Get("Authorization")
	assert.Equal(t, expectedAuthHeader, actualAuthHeader)

	// compare changed token in config
	actualToken, err := GetOAuthToken(config)
	assert.Nil(t, err)
	assert.Equal(t, *newToken, *actualToken)
	assert.Equal(t, *newToken, *authenticator.(*oAuth2Authenticator).token)
}

func Test_AddAuthenticationHeader_expiredToken(t *testing.T) {
	// prepare test
	expiredToken := &oauth2.Token{
		AccessToken:  "expired",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now().Add(-60 * time.Second),
	}

	newToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now().Add(60 * time.Second).UTC(),
	}

	config := configuration.NewInMemory()
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	authenticator.(*oAuth2Authenticator).persistToken(expiredToken)
	authenticator.(*oAuth2Authenticator).tokenRefresherFunc = func(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
		return newToken, nil
	}

	emptyRequest := &http.Request{
		Header: http.Header{},
	}

	// run method under test
	err := authenticator.AddAuthenticationHeader(emptyRequest)
	assert.Nil(t, err)

	// compare
	expectedAuthHeader := "Bearer " + newToken.AccessToken
	actualAuthHeader := emptyRequest.Header.Get("Authorization")
	assert.Equal(t, expectedAuthHeader, actualAuthHeader)

	// compare changed token in config
	actualToken, err := GetOAuthToken(config)
	assert.Nil(t, err)
	assert.Equal(t, *newToken, *actualToken)
	assert.Equal(t, *newToken, *authenticator.(*oAuth2Authenticator).token)
}

func Test_AddAuthenticationHeader_expiredToken_somebodyUpdated(t *testing.T) {
	// prepare test
	expiredToken := &oauth2.Token{
		AccessToken:  "expired",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now().Add(-60 * time.Second),
	}

	newToken := &oauth2.Token{
		AccessToken:  "a",
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now().Add(60 * time.Second).UTC(),
	}

	config := configuration.NewInMemory()
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	authenticator.(*oAuth2Authenticator).persistToken(expiredToken)
	authenticator.(*oAuth2Authenticator).tokenRefresherFunc = func(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
		assert.False(t, true, "The token is valid and no refresh is required!")
		return newToken, nil
	}

	emptyRequest := &http.Request{
		Header: http.Header{},
	}

	// have authenticator2 update the token "in parallel"
	authenticator2 := NewOAuth2AuthenticatorWithOpts(config)
	authenticator2.(*oAuth2Authenticator).persistToken(newToken)

	// run method under test
	err := authenticator.AddAuthenticationHeader(emptyRequest)
	assert.Nil(t, err)

	// compare
	expectedAuthHeader := "Bearer " + newToken.AccessToken
	actualAuthHeader := emptyRequest.Header.Get("Authorization")
	assert.Equal(t, expectedAuthHeader, actualAuthHeader)

	// compare changed token in config
	actualToken, err := GetOAuthToken(config)
	assert.Nil(t, err)
	assert.Equal(t, *newToken, *actualToken)
	assert.Equal(t, *newToken, *authenticator.(*oAuth2Authenticator).token)
}

func Test_determineGrantType_empty(t *testing.T) {
	config := configuration.NewInMemory()
	expected := AuthorizationCodeGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_determineGrantType_secret_only(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(PARAMETER_CLIENT_SECRET, "secret")
	expected := AuthorizationCodeGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_determineGrantType_id_only(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(PARAMETER_CLIENT_ID, "id")
	expected := AuthorizationCodeGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_determineGrantType_both(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(PARAMETER_CLIENT_ID, "id")
	config.Set(PARAMETER_CLIENT_SECRET, "secret")
	expected := ClientCredentialsGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_Authenticate_CredentialsGrant(t *testing.T) {
	go func() {
		mux := http.NewServeMux()
		srv := &http.Server{
			Handler:           mux,
			Addr:              "localhost:3221",
			ReadHeaderTimeout: time.Second * 30,
		}
		mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
			newToken := &oauth2.Token{
				AccessToken: "a",
				TokenType:   "b",
				Expiry:      time.Now().Add(60 * time.Second).UTC(),
			}
			data, err := json.Marshal(newToken)
			assert.Nil(t, err)

			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			_, err = w.Write(data)
			assert.Nil(t, err)
		})

		timer := time.AfterFunc(3*time.Second, func() {
			srv.Shutdown(context.Background())
		})

		srv.ListenAndServe()
		timer.Stop()
	}()

	config := configuration.NewInMemory()
	config.Set(PARAMETER_CLIENT_SECRET, "secret")
	config.Set(PARAMETER_CLIENT_ID, "id")
	config.Set(configuration.API_URL, "http://localhost:3221")

	authenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(http.DefaultClient))
	err := authenticator.Authenticate()
	assert.Nil(t, err)

	token := config.GetString(CONFIG_KEY_OAUTH_TOKEN)
	assert.NotEmpty(t, token)
}
