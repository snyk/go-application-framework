package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func headlessOpenBrowserFunc(t *testing.T) func(url string) {
	t.Helper()
	return func(url string) {
		fmt.Printf("Mock opening browser... %s\n", url)
		_, err := http.DefaultClient.Get(url)
		if err != nil {
			fmt.Printf("Error opening browser: %s\n", err)
		}
	}
}

func mockOAuth2TokenHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}

func mockAuthorizeHandler(state string, instance string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect to the redirect_uri with a mock authorization code
		redirectURI := r.URL.Query().Get("redirect_uri")

		if state == "" {
			state = r.URL.Query().Get("state")
		}

		instanceParam := ""
		if instance != "" {
			instanceParam = "&instance=" + instance
		}

		http.Redirect(w, r, redirectURI+"?code=mock-auth-code&state="+state+instanceParam, http.StatusFound)
	}
}

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

	expectedTokenString, err := json.Marshal(expectedToken)
	assert.NoError(t, err)

	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(expectedTokenString))

	// method under test
	actualToken, err := GetOAuthToken(config)
	assert.NoError(t, err)

	actualTokenString, err := json.Marshal(actualToken)
	assert.NoError(t, err)
	assert.Equal(t, expectedTokenString, actualTokenString)
}

func Test_getToken_NoToken_ReturnsNil(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "")

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.Nil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getToken_BadToken_ReturnsError(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, "something else")

	// method under test
	actualToken, err := GetOAuthToken(config)

	assert.NotNil(t, err)
	assert.Nil(t, actualToken)
}

func Test_getOAuthConfiguration(t *testing.T) {
	webapp := "https://app.fedramp-alpha.snykgov.io"
	api := "https://api.fedramp-alpha.snykgov.io"

	config := configuration.NewWithOpts()
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

	config := configuration.NewWithOpts()
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	err := authenticator.(*oAuth2Authenticator).persistToken(newToken) //nolint:errcheck //in this test, the type is clear
	assert.NoError(t, err)
	authenticator.(*oAuth2Authenticator).tokenRefresherFunc = func(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) { //nolint:errcheck //in this test, the type is clear
		assert.False(t, true, "The token is valid and no refresh is required!")
		return newToken, nil
	}

	emptyRequest := &http.Request{
		Header: http.Header{},
	}

	// run method under test
	err = authenticator.AddAuthenticationHeader(emptyRequest)
	assert.NoError(t, err)

	// compare
	expectedAuthHeader := "Bearer " + newToken.AccessToken
	actualAuthHeader := emptyRequest.Header.Get("Authorization")
	assert.Equal(t, expectedAuthHeader, actualAuthHeader)

	// compare changed token in config
	actualToken, err := GetOAuthToken(config)
	assert.NoError(t, err)
	assert.Equal(t, *newToken, *actualToken)
	assert.Equal(t, *newToken, *authenticator.(*oAuth2Authenticator).token) //nolint:errcheck //in this test, the type is clear
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

	config := configuration.NewWithOpts()
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	err := authenticator.(*oAuth2Authenticator).persistToken(expiredToken) //nolint:errcheck //in this test, the type is clear
	assert.NoError(t, err)
	authenticator.(*oAuth2Authenticator).tokenRefresherFunc = func(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) { //nolint:errcheck //in this test, the type is clear
		return newToken, nil
	}

	emptyRequest := &http.Request{
		Header: http.Header{},
	}

	// run method under test
	err = authenticator.AddAuthenticationHeader(emptyRequest)
	assert.NoError(t, err)

	// compare
	expectedAuthHeader := "Bearer " + newToken.AccessToken
	actualAuthHeader := emptyRequest.Header.Get("Authorization")
	assert.Equal(t, expectedAuthHeader, actualAuthHeader)

	// compare changed token in config
	actualToken, err := GetOAuthToken(config)
	assert.NoError(t, err)
	assert.Equal(t, *newToken, *actualToken)
	assert.Equal(t, *newToken, *authenticator.(*oAuth2Authenticator).token) //nolint:errcheck //in this test, the type is clear
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

	config := configuration.NewWithOpts()
	authenticator := NewOAuth2AuthenticatorWithOpts(config)
	err := authenticator.(*oAuth2Authenticator).persistToken(expiredToken) //nolint:errcheck //in this test, the type is clear
	assert.NoError(t, err)
	authenticator.(*oAuth2Authenticator).tokenRefresherFunc = func(_ context.Context, _ *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) { //nolint:errcheck //in this test, the type is clear
		assert.False(t, true, "The token is valid and no refresh is required!")
		return newToken, nil
	}

	emptyRequest := &http.Request{
		Header: http.Header{},
	}

	// have authenticator2 update the token "in parallel"
	authenticator2 := NewOAuth2AuthenticatorWithOpts(config)
	err = authenticator2.(*oAuth2Authenticator).persistToken(newToken) //nolint:errcheck //in this test, the type is clear
	assert.NoError(t, err)

	// run method under test
	err = authenticator.AddAuthenticationHeader(emptyRequest)
	assert.NoError(t, err)

	// compare
	expectedAuthHeader := "Bearer " + newToken.AccessToken
	actualAuthHeader := emptyRequest.Header.Get("Authorization")
	assert.Equal(t, expectedAuthHeader, actualAuthHeader)

	// compare changed token in config
	actualToken, err := GetOAuthToken(config)
	assert.NoError(t, err)
	assert.Equal(t, *newToken, *actualToken)
	assert.Equal(t, *newToken, *authenticator.(*oAuth2Authenticator).token) //nolint:errcheck //in this test, the type is clear
}

func Test_determineGrantType_empty(t *testing.T) {
	config := configuration.NewWithOpts()
	expected := AuthorizationCodeGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_determineGrantType_secret_only(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(PARAMETER_CLIENT_SECRET, "secret")
	expected := AuthorizationCodeGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_determineGrantType_id_only(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(PARAMETER_CLIENT_ID, "id")
	expected := AuthorizationCodeGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_determineGrantType_both(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(PARAMETER_CLIENT_ID, "id")
	config.Set(PARAMETER_CLIENT_SECRET, "secret")
	expected := ClientCredentialsGrant
	actual := determineGrantType(config)
	assert.Equal(t, expected, actual)
}

func Test_Authenticate_CredentialsGrant(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
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

	config := configuration.NewWithOpts()
	config.Set(PARAMETER_CLIENT_SECRET, "secret")
	config.Set(PARAMETER_CLIENT_ID, "id")
	config.Set(configuration.API_URL, srv.URL)

	authenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(http.DefaultClient))
	err := authenticator.Authenticate()
	assert.Nil(t, err)

	token := config.GetString(CONFIG_KEY_OAUTH_TOKEN)
	assert.NotEmpty(t, token)
}

func Test_Authenticate_AuthorizationCode(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		config := configuration.NewWithOpts()

		// Create mock server for successful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", mockAuthorizeHandler("", ""))
		mux.HandleFunc("/oauth2/token", mockOAuth2TokenHandler(t))
		ts := httptest.NewServer(mux)
		defer ts.Close()

		config.Set(configuration.API_URL, ts.URL)
		config.Set(configuration.WEB_APP_URL, ts.URL)

		authenticator := NewOAuth2AuthenticatorWithOpts(
			config,
			WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)

		err := authenticator.Authenticate()
		assert.Nil(t, err)

		assert.Equal(t, "{\"access_token\":\"a\",\"token_type\":\"b\",\"expiry\":\"0001-01-01T00:00:00Z\"}", config.GetString(CONFIG_KEY_OAUTH_TOKEN))
	})

	t.Run("supports redirect to valid instance", func(t *testing.T) {
		tokenServer := httptest.NewServer(mockOAuth2TokenHandler(t))
		defer tokenServer.Close()

		// Create mock server for successful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", mockAuthorizeHandler("", tokenServer.URL))
		initialAuthServer := httptest.NewServer(mux)
		defer initialAuthServer.Close()

		config := configuration.NewWithOpts()
		config.Set(CONFIG_KEY_ALLOWED_HOST_REGEXP, ".*")
		config.Set(configuration.API_URL, initialAuthServer.URL)
		config.Set(configuration.WEB_APP_URL, initialAuthServer.URL)

		authenticator := NewOAuth2AuthenticatorWithOpts(
			config,
			WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)

		err := authenticator.Authenticate()
		assert.NoError(t, err)
		assert.Equal(t, "{\"access_token\":\"a\",\"token_type\":\"b\",\"expiry\":\"0001-01-01T00:00:00Z\"}", config.GetString(CONFIG_KEY_OAUTH_TOKEN))
	})

	t.Run("does not redirect to invalid instance", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(CONFIG_KEY_ALLOWED_HOST_REGEXP, constants.SNYK_DEFAULT_ALLOWED_HOST_REGEXP)

		// Create mock server for successful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", mockAuthorizeHandler("", "api.malicioussnyk.io"))
		mux.HandleFunc("/oauth2/token", mockOAuth2TokenHandler(t))

		ts := httptest.NewServer(mux)
		defer ts.Close()

		config.Set(configuration.WEB_APP_URL, ts.URL)
		config.Set(configuration.API_URL, ts.URL)
		authenticator := NewOAuth2AuthenticatorWithOpts(
			config,
			WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)

		err := authenticator.Authenticate()
		assert.ErrorContains(t, err, "invalid host")
	})

	t.Run("fails with malformed state", func(t *testing.T) {
		config := configuration.NewWithOpts()

		// Create mock server for unsuccessful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", mockAuthorizeHandler("incorrect-state", ""))
		mux.HandleFunc("/oauth2/token", mockOAuth2TokenHandler(t))
		ts := httptest.NewServer(mux)
		defer ts.Close()

		config.Set(configuration.API_URL, ts.URL)
		config.Set(configuration.WEB_APP_URL, ts.URL)

		authenticator := NewOAuth2AuthenticatorWithOpts(
			config,
			WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)

		err := authenticator.Authenticate()
		assert.ErrorContains(t, err, "incorrect response state")
	})
}

func Test_CancellableAuthenticate_AuthorizationCodeGrant_ContextCanceled(t *testing.T) {
	t.Parallel()

	// Setup

	config := configuration.NewWithOpts()
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authCtx, cancelAuthCtx := context.WithCancel(context.Background())
	t.Cleanup(cancelAuthCtx) // For safety to prevent resource leaks

	mockMux := http.NewServeMux()
	mockMux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		cancelAuthCtx()
		w.WriteHeader(http.StatusOK)
	})
	mockExternalOAuthServer := httptest.NewServer(mockMux)
	defer mockExternalOAuthServer.Close()

	config.Set(configuration.API_URL, mockExternalOAuthServer.URL)
	config.Set(configuration.WEB_APP_URL, mockExternalOAuthServer.URL)

	authenticator, ok := NewOAuth2AuthenticatorWithOpts(
		config,
		WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		WithShutdownServerFunc(ShutdownServer),
	).(*oAuth2Authenticator)
	require.True(t, ok, "Expected to create an oAuth2Authenticator")
	require.Equal(t, AuthorizationCodeGrant, authenticator.grantType, "Authenticator should be in AuthorizationCodeGrant mode")

	// Act

	// Run the auth async and post the result on a channel, so we can set a timeout.
	authErrChannel := make(chan error, 1)
	go func() {
		authErrChannel <- authenticator.CancelableAuthenticate(authCtx) // authCtx will be canceled by the mock server.
	}()

	// Wait and assert

	select {
	case authErr := <-authErrChannel:
		assert.ErrorIs(t, authErr, ErrAuthCanceled)
		assert.ErrorIs(t, authCtx.Err(), context.Canceled, "CancellableAuthenticate may not have \"opened the browser\" to trigger the cancel.")
	case <-time.After(2 * time.Second):
		t.Fatal("Test timed out after 2 seconds waiting for CancellableAuthenticate to return, which should have been canceled.")
	}
}
