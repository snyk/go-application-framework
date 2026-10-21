package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func newRequestForHeaders(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://localhost/some/path", http.NoBody)
	require.NoError(t, err)
	return req
}

func Test_CreateAuthenticator_StoredValidOAuthTokenAndFlagOn_SendsBearerAccessToken(t *testing.T) {
	token := &oauth2.Token{
		AccessToken:  "stored-access-token",
		TokenType:    "bearer",
		RefreshToken: "stored-refresh-token",
		Expiry:       time.Now().Add(20 * time.Minute).UTC(),
	}
	tokenJSON, err := json.Marshal(token)
	require.NoError(t, err)

	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(tokenJSON))
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	req := newRequestForHeaders(t)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Equal(t, "Bearer stored-access-token", req.Header.Get("Authorization"))
	assert.Equal(t, "Bearer stored-access-token", req.Header.Get("Session-Token"))
}

func Test_CreateAuthenticator_OAuthFlagOffAndStoredLegacyToken_SendsTokenScheme(t *testing.T) {
	tokenJSON, err := json.Marshal(&oauth2.Token{
		AccessToken: "ignored-oauth-token",
		Expiry:      time.Now().Add(20 * time.Minute).UTC(),
	})
	require.NoError(t, err)

	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(tokenJSON))
	config.Set(configuration.AUTHENTICATION_TOKEN, "legacy-api-token")
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, false)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	req := newRequestForHeaders(t)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Equal(t, "token legacy-api-token", req.Header.Get("Authorization"))
	assert.Equal(t, "token legacy-api-token", req.Header.Get("Session-Token"))
}

func Test_CreateAuthenticator_OAuthFlagOnNoStoredOAuthTokenAndLegacyToken_FallsBackToTokenScheme(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, "legacy-api-token")
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "")
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	req := newRequestForHeaders(t)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Equal(t, "token legacy-api-token", req.Header.Get("Authorization"))
	assert.Equal(t, "token legacy-api-token", req.Header.Get("Session-Token"))
}

func Test_CreateAuthenticator_NothingStored_AddsNoAuthHeadersAndNoError(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := CreateAuthenticator(config, http.DefaultClient)
	req := newRequestForHeaders(t)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Empty(t, req.Header.Values("Authorization"))
	assert.Empty(t, req.Header.Values("Session-Token"))
}

func Test_CreateAuthenticator_ExpiredOAuthTokenWithRefreshToken_RefreshesThroughTokenEndpointAndPersists(t *testing.T) {
	var refreshCalls atomic.Int32
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalls.Add(1)
		assert.Equal(t, "/oauth2/token", r.URL.Path)
		assert.NoError(t, r.ParseForm())
		gotForm = r.Form

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed-access-token",
			"token_type":    "bearer",
			"refresh_token": "rotated-refresh-token",
			"expires_in":    3600,
		}))
	}))
	t.Cleanup(srv.Close)

	expired, err := json.Marshal(&oauth2.Token{
		AccessToken:  "expired-access-token",
		TokenType:    "bearer",
		RefreshToken: "original-refresh-token",
		Expiry:       time.Now().Add(-time.Minute).UTC(),
	})
	require.NoError(t, err)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, string(expired))
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := CreateAuthenticator(config, srv.Client())
	req := newRequestForHeaders(t)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Equal(t, int32(1), refreshCalls.Load())
	assert.Equal(t, "refresh_token", gotForm.Get("grant_type"))
	assert.Equal(t, "original-refresh-token", gotForm.Get("refresh_token"))
	assert.Equal(t, "Bearer refreshed-access-token", req.Header.Get("Authorization"))
	assert.Equal(t, "Bearer refreshed-access-token", req.Header.Get("Session-Token"))

	persisted, err := GetOAuthToken(config)
	require.NoError(t, err)
	require.NotNil(t, persisted)
	assert.Equal(t, "refreshed-access-token", persisted.AccessToken)
	assert.Equal(t, "rotated-refresh-token", persisted.RefreshToken)
	assert.True(t, persisted.Valid())
}
