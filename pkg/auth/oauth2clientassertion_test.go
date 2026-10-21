package auth

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type fakeAssertionProvider struct {
	clientID string
	tokenURL string
	calls    int
}

func (f *fakeAssertionProvider) ClientAssertion(_ context.Context, clientID, tokenURL string) (string, string, error) {
	f.calls++
	f.clientID = clientID
	f.tokenURL = tokenURL
	return "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "fake-assertion", nil
}

func Test_Authenticate_ClientAssertionGrant(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var gotForm url.Values
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotForm = r.Form

		newToken := &oauth2.Token{
			AccessToken: "a",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(60 * time.Second).UTC(),
		}
		data, err := json.Marshal(newToken)
		assert.NoError(t, err)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, err = w.Write(data)
		assert.NoError(t, err)
	})

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, srv.URL)

	provider := &fakeAssertionProvider{}
	authenticator := NewOAuth2AuthenticatorWithOpts(
		config,
		WithHttpClient(http.DefaultClient),
		WithClientAssertionProvider("machine-client-1", provider),
	)

	err := authenticator.Authenticate()
	require.NoError(t, err)

	token := config.GetString(CONFIG_KEY_OAUTH_TOKEN)
	assert.NotEmpty(t, token)

	assert.Equal(t, 1, provider.calls)
	assert.Equal(t, "machine-client-1", provider.clientID)
	assert.Contains(t, provider.tokenURL, "/oauth2/token")

	assert.Equal(t, "machine-client-1", gotForm.Get("client_id"))
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", gotForm.Get("client_assertion_type"))
	assert.Equal(t, "fake-assertion", gotForm.Get("client_assertion"))
	assert.Empty(t, gotForm.Get("client_secret"), "a client assertion must not be combined with a static client secret")
}

func Test_IsSupported_ClientAssertionProvider(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	authenticator := NewOAuth2AuthenticatorWithOpts(
		config,
		WithClientAssertionProvider("machine-client-1", &fakeAssertionProvider{}),
	)

	assert.True(t, authenticator.IsSupported(), "a client assertion provider should count as having a credential, even without a stored token")
}

func Test_AddAuthenticationHeader_ClientAssertionGrant(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		newToken := &oauth2.Token{
			AccessToken: "a",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(60 * time.Second).UTC(),
		}
		data, err := json.Marshal(newToken)
		assert.NoError(t, err)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, err = w.Write(data)
		assert.NoError(t, err)
	})

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, srv.URL)

	provider := &fakeAssertionProvider{}
	authenticator := NewOAuth2AuthenticatorWithOpts(
		config,
		WithHttpClient(http.DefaultClient),
		WithClientAssertionProvider("machine-client-1", provider),
	)

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	oauthAuthenticator, ok := authenticator.(*oAuth2Authenticator)
	require.True(t, ok)
	require.NoError(t, oauthAuthenticator.AddAuthenticationHeader(req))

	assert.Equal(t, "Bearer a", req.Header.Get("Authorization"))
	assert.Equal(t, 1, provider.calls, "no stored token yet, so a fresh one must be fetched via the assertion provider")
}

func newFileBackedAssertionAuthenticator(t *testing.T, apiURL string, provider *fakeAssertionProvider) (*oAuth2Authenticator, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "snyk.json")
	config := configuration.NewWithOpts()
	config.SetStorage(configuration.NewJsonStorage(path, configuration.WithConfiguration(config)))
	config.Set(configuration.API_URL, apiURL)

	var authenticator Authenticator = NewOAuth2AuthenticatorWithOpts(
		config,
		WithHttpClient(http.DefaultClient),
		WithClientAssertionProvider("machine-client-1", provider),
	)
	oauthAuthenticator, ok := authenticator.(*oAuth2Authenticator)
	require.True(t, ok)
	return oauthAuthenticator, path
}

func Test_AddAuthenticationHeader_ClientAssertionGrant_ConfigFileDoesNotExistYet(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(&oauth2.Token{AccessToken: "a", TokenType: "bearer", Expiry: time.Now().Add(60 * time.Second).UTC()})
		assert.NoError(t, err)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, err = w.Write(data)
		assert.NoError(t, err)
	})

	provider := &fakeAssertionProvider{}
	authenticator, path := newFileBackedAssertionAuthenticator(t, srv.URL, provider)

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	require.NoError(t, authenticator.AddAuthenticationHeader(req))

	assert.Equal(t, "Bearer a", req.Header.Get("Authorization"))
	assert.Equal(t, 1, provider.calls)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(contents, &doc))
	storedToken, ok := doc[CONFIG_KEY_OAUTH_TOKEN].(string)
	require.True(t, ok, "the minted token is persisted")
	var token oauth2.Token
	require.NoError(t, json.Unmarshal([]byte(storedToken), &token))
	assert.Equal(t, "a", token.AccessToken)
}

func Test_AddAuthenticationHeader_ClientAssertionGrant_CorruptConfigFileStillFails(t *testing.T) {
	provider := &fakeAssertionProvider{}
	authenticator, path := newFileBackedAssertionAuthenticator(t, "https://example.invalid", provider)
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	assert.Error(t, authenticator.AddAuthenticationHeader(req))
	assert.Equal(t, 0, provider.calls)
}

func Test_AddAuthenticationHeader_TokenOnly_ConfigFileDoesNotExistStillFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snyk.json")
	config := configuration.NewWithOpts()
	config.SetStorage(configuration.NewJsonStorage(path, configuration.WithConfiguration(config)))

	authenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(http.DefaultClient))
	oauthAuthenticator, ok := authenticator.(*oAuth2Authenticator)
	require.True(t, ok)
	oauthAuthenticator.token = &oauth2.Token{AccessToken: "expired", Expiry: time.Now().Add(-time.Hour)}

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	assert.ErrorIs(t, oauthAuthenticator.AddAuthenticationHeader(req), fs.ErrNotExist)
}
