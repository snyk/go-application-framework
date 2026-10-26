package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type fakeAssertionProvider struct {
	clientID string
	tokenURL string
	calls    int
	err      error
}

func (f *fakeAssertionProvider) ClientAssertion(_ context.Context, clientID, tokenURL string) (string, string, error) {
	f.calls++
	f.clientID = clientID
	f.tokenURL = tokenURL
	if f.err != nil {
		return "", "", f.err
	}
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

func tokenEndpointRespondingWith(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, err := w.Write([]byte(`{"error":"invalid_client"}`))
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// hostErrorHandlerClient behaves like an unauthorized client whose host installed a network error
// handler: a rejected request comes back as an error catalog error and the response is dropped.
func hostErrorHandlerClient() *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		_ = res.Body.Close()
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return res, snyk.NewUnauthorisedError("Use `snyk auth` to authenticate.")
		case http.StatusBadRequest:
			return res, snyk.NewBadRequestError("The request cannot be processed.")
		}
		return res, nil
	})}
}

func addMachineAuthenticationHeader(t *testing.T, apiURL string, client *http.Client) error {
	t.Helper()
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, apiURL)
	authenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(client), WithClientAssertionProvider("machine-client-1", &fakeAssertionProvider{}))
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	err = authenticator.AddAuthenticationHeader(req)
	assert.Empty(t, req.Header.Values("Authorization"))
	return err
}

func Test_AddAuthenticationHeader_ClientAssertionGrant_TokenEndpointRejectsTheMachine(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := tokenEndpointRespondingWith(t, status)

			for name, test := range map[string]struct {
				client *http.Client
				cause  func(t *testing.T, err error)
			}{
				"without a host error handler": {
					client: http.DefaultClient,
					cause: func(t *testing.T, err error) {
						t.Helper()
						var retrieveErr *oauth2.RetrieveError
						assert.ErrorAs(t, err, &retrieveErr)
					},
				},
				"with a host error handler": {
					client: hostErrorHandlerClient(),
					cause: func(t *testing.T, err error) {
						t.Helper()
						var catalogErr snyk_errors.Error
						assert.False(t, errors.As(err, &catalogErr), "a catalog error would make hosts show its detail instead: %v", err)
					},
				},
			} {
				t.Run(name, func(t *testing.T) {
					err := addMachineAuthenticationHeader(t, srv.URL, test.client)

					var machineErr *machinecredential.AuthenticationError
					require.ErrorAs(t, err, &machineErr)
					assert.ErrorContains(t, err, "machine authentication failed")
					assert.ErrorContains(t, err, srv.URL+"/oauth2/token")
					assert.ErrorContains(t, err, "machine-client-1")
					assert.ErrorContains(t, err, "enrolled in another region or its client was revoked")
					assert.ErrorContains(t, err, "`snyk config environment`")
					assert.ErrorContains(t, err, "enroll this machine again")
					assert.NotContains(t, err.Error(), "snyk auth")
					test.cause(t, err)
				})
			}
		})
	}
}

func Test_AddAuthenticationHeader_ClientAssertionGrant_TokenEndpointFailsOtherwise(t *testing.T) {
	srv := tokenEndpointRespondingWith(t, http.StatusInternalServerError)

	err := addMachineAuthenticationHeader(t, srv.URL, http.DefaultClient)

	var machineErr *machinecredential.AuthenticationError
	require.ErrorAs(t, err, &machineErr)
	assert.ErrorContains(t, err, srv.URL+"/oauth2/token")
	assert.ErrorContains(t, err, "machine-client-1")
	assert.NotContains(t, err.Error(), "another region")
}

func Test_AddAuthenticationHeader_HumanOAuthRefreshRejected_IsNotAMachineAuthenticationError(t *testing.T) {
	srv := tokenEndpointRespondingWith(t, http.StatusBadRequest)
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, srv.URL)
	authenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(http.DefaultClient))
	oauthAuthenticator, ok := authenticator.(*oAuth2Authenticator)
	require.True(t, ok)
	oauthAuthenticator.token = &oauth2.Token{AccessToken: "expired", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Hour)}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	err = oauthAuthenticator.AddAuthenticationHeader(req)

	require.Error(t, err)
	var machineErr *machinecredential.AuthenticationError
	assert.False(t, errors.As(err, &machineErr))
}

func Test_AddAuthenticationHeader_ClientAssertionGrant_SigningFails(t *testing.T) {
	errSigning := errors.New("signing failed")
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	authenticator := NewOAuth2AuthenticatorWithOpts(config, WithHttpClient(http.DefaultClient), WithClientAssertionProvider("machine-client-1", &fakeAssertionProvider{err: errSigning}))
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	err = authenticator.AddAuthenticationHeader(req)

	var machineErr *machinecredential.AuthenticationError
	require.ErrorAs(t, err, &machineErr)
	assert.ErrorIs(t, err, errSigning)
	assert.ErrorContains(t, err, "machine-client-1")
	assert.Empty(t, req.Header.Values("Authorization"))
}
