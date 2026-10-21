package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const testSubjectToken = "subject-token"

func Test_bearerTokenScoperImpl_GetToken(t *testing.T) {
	const subjectToken = "subject-token"
	const scopedToken = "scoped-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth2/token", r.URL.Path)
		assert.Equal(t, "3600", r.URL.Query().Get("ttl"))
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.PostForm.Get("grant_type"))
		assert.Equal(t, subjectToken, r.PostForm.Get("subject_token"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", r.PostForm.Get("subject_token_type"))
		assert.Equal(t, "tenant.supplychain.registry.read org.read", r.PostForm.Get("scope"))
		assert.Empty(t, r.PostForm.Get("ttl"))
		assert.Empty(t, r.PostForm.Get("client_id"))
		assert.Empty(t, r.PostForm.Get("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"access_token":"` + scopedToken + `","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"bearer","expires_in":2874,"scope":"tenant.supplychain.registry.read org.read"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := newStoredTokenConfig(server.URL)

	scoper := NewBearerTokenScoper(config, singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"tenant.supplychain.registry.read", "org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, scopedToken, token)
}

func Test_bearerTokenScoperImpl_GetToken_WithoutTTL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.URL.RawQuery)

		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"access_token":"scoped-token","token_type":"bearer","expires_in":2874}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, 0)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

func Test_bearerTokenScoperImpl_GetToken_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"error":"invalid_request"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Error(t, err)
	assert.Empty(t, token)
}

type fakeNetworkClients struct {
	authenticated *http.Client
	unauthorized  *http.Client
}

func (f fakeNetworkClients) GetHttpClient() *http.Client { return f.authenticated }

func (f fakeNetworkClients) GetUnauthorizedHttpClient() *http.Client { return f.unauthorized }

func singleClient(client *http.Client) fakeNetworkClients {
	return fakeNetworkClients{authenticated: client, unauthorized: client}
}

func newStoredTokenConfig(apiURL string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, apiURL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"`+testSubjectToken+`","token_type":"Bearer"}`)
	return config
}

func catalogErrorOf(t *testing.T, err error) snyk_errors.Error {
	t.Helper()
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	return catalogErr
}

func requireCatalogError(t *testing.T, err error, errorCode string) {
	t.Helper()
	require.Equal(t, errorCode, catalogErrorOf(t, err).ErrorCode)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func Test_bearerTokenScoperImpl_GetToken_NetworkFailureKeepsCause(t *testing.T) {
	sentinel := errors.New("sentinel transport failure")
	httpClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, sentinel
	})}

	scoper := NewBearerTokenScoper(newStoredTokenConfig("https://api.example.invalid"), singleClient(httpClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, cli.NewTokenScoperError("").ErrorCode)
	assert.ErrorIs(t, err, sentinel)
	assert.Empty(t, token)
}

func requireNoSecretLeak(t *testing.T, err error, secret string) {
	t.Helper()
	catalogErr := catalogErrorOf(t, err)
	assert.NotContains(t, catalogErr.Detail, secret)
	assert.NotContains(t, err.Error(), secret)
	for _, value := range catalogErr.Meta {
		assert.NotContains(t, fmt.Sprint(value), secret)
	}
}

func Test_bearerTokenScoperImpl_GetToken_ErrorBodyKeepsOnlyOAuthErrorFields(t *testing.T) {
	tests := []struct {
		name      string
		configure func(configuration.Configuration)
		secret    string
	}{
		{
			name: "stored oauth access token",
			configure: func(c configuration.Configuration) {
				c.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"stored-access-token","token_type":"Bearer"}`)
			},
			secret: "stored-access-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, err := fmt.Fprintf(w, `{"error":"invalid_request","error_description":"token rejected","echo":"%s"}`, tt.secret)
				assert.NoError(t, err)
			}))
			defer server.Close()

			config := configuration.NewWithOpts()
			config.Set(configuration.API_URL, server.URL)
			tt.configure(config)

			scoper := NewBearerTokenScoper(config, singleClient(server.Client()))
			token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

			require.Empty(t, token)
			catalogErr := catalogErrorOf(t, err)
			assert.Contains(t, catalogErr.Detail, "invalid_request")
			assert.Contains(t, catalogErr.Detail, "token rejected")
			assert.NotContains(t, catalogErr.Meta, "body")
			assert.NotContains(t, catalogErr.Meta, "echo")
			requireNoSecretLeak(t, err, tt.secret)
		})
	}
}

func Test_bearerTokenScoperImpl_GetToken_UnparseableErrorBodyStoresNothing(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"non-json", "upstream says: " + testSubjectToken},
		{"oversized", `{"error":"invalid_request","error_description":"` + strings.Repeat("a", 2<<20) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, err := w.Write([]byte(tt.body))
				assert.NoError(t, err)
			}))
			defer server.Close()

			scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
			token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

			require.Empty(t, token)
			catalogErr := catalogErrorOf(t, err)
			assert.Equal(t, cli.NewTokenScoperError("").ErrorCode, catalogErr.ErrorCode)
			assert.Empty(t, catalogErr.Meta)
			requireNoSecretLeak(t, err, testSubjectToken)
		})
	}
}

func Test_bearerTokenScoperImpl_GetToken_ServerErrorWithUnreadableBodyKeepsCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("partial"))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, cli.NewTokenScoperError("").ErrorCode)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_TruncatedBodyStoresNothing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"error":"invalid_request"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, cli.NewTokenScoperError("").ErrorCode)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Empty(t, catalogErrorOf(t, err).Meta)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_PlainClientNon200ReturnsScoperErrorWithStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte(`{"error":"invalid_client","error_description":"bad subject"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Empty(t, token)
	catalogErr := catalogErrorOf(t, err)
	require.Equal(t, cli.NewTokenScoperError("").ErrorCode, catalogErr.ErrorCode)
	assert.Contains(t, catalogErr.Detail, "401")
	assert.Contains(t, catalogErr.Detail, "invalid_client")
	assert.Contains(t, catalogErr.Detail, "bad subject")
	requireNoSecretLeak(t, err, testSubjectToken)
}

func Test_bearerTokenScoperImpl_GetToken_TransportCatalogErrorIsWrappedWithCause(t *testing.T) {
	middlewareErr := snyk.NewUnauthorisedError("x")
	httpClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, middlewareErr
	})}

	scoper := NewBearerTokenScoper(newStoredTokenConfig("https://api.example.invalid"), singleClient(httpClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, cli.NewTokenScoperError("").ErrorCode)
	var causeErr snyk_errors.Error
	require.ErrorAs(t, catalogErrorOf(t, err).Cause, &causeErr)
	assert.Equal(t, middlewareErr.ErrorCode, causeErr.ErrorCode)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_NoUserAuthentication(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")

	scoper := NewBearerTokenScoper(config, singleClient(http.DefaultClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	assert.Equal(t, "no user authentication is available", catalogErrorOf(t, err).Detail)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"token_type":"bearer","expires_in":2874}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Empty(t, token)
	catalogErr := catalogErrorOf(t, err)
	require.Equal(t, cli.NewTokenScoperError("").ErrorCode, catalogErr.ErrorCode)
	assert.Equal(t, "token exchange response did not contain an access token", catalogErr.Detail)
}

func Test_bearerTokenScoperImpl_GetToken_DecodeFailureKeepsCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`not-json`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, cli.NewTokenScoperError("").ErrorCode)
	var syntaxErr *json.SyntaxError
	assert.ErrorAs(t, err, &syntaxErr)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_TruncatedErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("partial"))
		assert.NoError(t, err)
	}))
	defer server.Close()

	scoper := NewBearerTokenScoper(newStoredTokenConfig(server.URL), singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, cli.NewTokenScoperError("").ErrorCode)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_FallsBackToStoredOAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "stored-access-token", r.PostForm.Get("subject_token"))

		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"access_token":"scoped-token","token_type":"bearer","expires_in":2874}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"stored-access-token","token_type":"Bearer"}`)

	scoper := NewBearerTokenScoper(config, singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

func Test_bearerTokenScoperImpl_GetToken_RefreshesExpiredStoredOAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")

		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			assert.Equal(t, "stored-refresh-token", r.PostForm.Get("refresh_token"))
			_, err := w.Write([]byte(`{"access_token":"refreshed-access-token","token_type":"Bearer","refresh_token":"stored-refresh-token","expires_in":3600}`))
			assert.NoError(t, err)
		case grantTypeTokenExchange:
			assert.Equal(t, "refreshed-access-token", r.PostForm.Get("subject_token"))
			_, err := w.Write([]byte(`{"access_token":"scoped-token","token_type":"bearer","expires_in":2874}`))
			assert.NoError(t, err)
		default:
			assert.Fail(t, "unexpected grant type", r.PostForm.Get("grant_type"))
		}
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"stored-access-token","token_type":"Bearer","refresh_token":"stored-refresh-token","expiry":"2001-01-01T00:00:00Z"}`)

	scoper := NewBearerTokenScoper(config, singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
	assert.Contains(t, config.GetString(CONFIG_KEY_OAUTH_TOKEN), "refreshed-access-token")
}

func Test_bearerTokenScoperImpl_GetToken_RefreshesStoredOAuthTokenWithEmptyAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")

		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			assert.Equal(t, "stored-refresh-token", r.PostForm.Get("refresh_token"))
			_, err := w.Write([]byte(`{"access_token":"refreshed-access-token","token_type":"Bearer","refresh_token":"stored-refresh-token","expires_in":3600}`))
			assert.NoError(t, err)
		case grantTypeTokenExchange:
			assert.Equal(t, "refreshed-access-token", r.PostForm.Get("subject_token"))
			_, err := w.Write([]byte(`{"access_token":"scoped-token","token_type":"bearer","expires_in":2874}`))
			assert.NoError(t, err)
		default:
			assert.Fail(t, "unexpected grant type", r.PostForm.Get("grant_type"))
		}
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"token_type":"Bearer","refresh_token":"stored-refresh-token","expiry":"2001-01-01T00:00:00Z"}`)

	scoper := NewBearerTokenScoper(config, singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

const expiredOAuthToken = `{"access_token":"stored-access-token","token_type":"Bearer","refresh_token":"stored-refresh-token","expiry":"2001-01-01T00:00:00Z"}`

func newExpiredTokenConfig(apiURL string) configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, apiURL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, expiredOAuthToken)
	return config
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func refreshOrExchangeResponse(grantType string) string {
	if grantType == "refresh_token" {
		return `{"access_token":"refreshed-access-token","token_type":"Bearer","refresh_token":"stored-refresh-token","expires_in":3600}`
	}
	return `{"access_token":"scoped-token","token_type":"bearer","expires_in":2874}`
}

func newRefreshAndExchangeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(refreshOrExchangeResponse(r.PostForm.Get("grant_type"))))
		assert.NoError(t, err)
	}))
}

func Test_bearerTokenScoperImpl_GetToken_RefreshAndExchangeUseTheirOwnClients(t *testing.T) {
	var refreshGrants, exchangeGrants []string
	newRecordingClient := func(grants *[]string) *http.Client {
		return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			grantType := r.PostForm.Get("grant_type")
			*grants = append(*grants, grantType)
			return jsonResponse(refreshOrExchangeResponse(grantType)), nil
		})}
	}
	clients := fakeNetworkClients{
		authenticated: newRecordingClient(&exchangeGrants),
		unauthorized:  newRecordingClient(&refreshGrants),
	}

	scoper := NewBearerTokenScoper(newExpiredTokenConfig("https://api.example.invalid"), clients)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
	assert.Equal(t, []string{"refresh_token"}, refreshGrants)
	assert.Equal(t, []string{grantTypeTokenExchange}, exchangeGrants)
}

func Test_bearerTokenScoperImpl_GetToken_NilNetworkClientsFallsBackToDefaultClient(t *testing.T) {
	server := newRefreshAndExchangeServer(t)
	defer server.Close()

	scoper := NewBearerTokenScoper(newExpiredTokenConfig(server.URL), nil)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

func Test_bearerTokenScoperImpl_GetToken_NilUnauthorizedClientFallsBackToDefaultClient(t *testing.T) {
	server := newRefreshAndExchangeServer(t)
	defer server.Close()

	clients := fakeNetworkClients{authenticated: server.Client(), unauthorized: nil}
	scoper := NewBearerTokenScoper(newExpiredTokenConfig(server.URL), clients)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

func Test_bearerTokenScoperImpl_GetToken_NilAuthenticatedClientFallsBackToDefaultClient(t *testing.T) {
	server := newRefreshAndExchangeServer(t)
	defer server.Close()

	clients := fakeNetworkClients{authenticated: nil, unauthorized: server.Client()}
	scoper := NewBearerTokenScoper(newExpiredTokenConfig(server.URL), clients)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

func Test_bearerTokenScoperImpl_GetToken_BearerTokenOnlyIsNotUserAuthentication(t *testing.T) {
	unexpectedClient := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Error("no HTTP request is expected without a stored user token")
		return nil, errors.New("unexpected request")
	})}
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "bearer-token")

	scoper := NewBearerTokenScoper(config, singleClient(unexpectedClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	assert.Equal(t, "no user authentication is available", catalogErrorOf(t, err).Detail)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_FailedRefreshOfExpiredStoredOAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.PostForm.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"error":"invalid_grant"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"stored-access-token","token_type":"Bearer","refresh_token":"stored-refresh-token","expiry":"2001-01-01T00:00:00Z"}`)

	scoper := NewBearerTokenScoper(config, singleClient(server.Client()))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	var retrieveErr *oauth2.RetrieveError
	assert.ErrorAs(t, err, &retrieveErr)
	assert.Empty(t, token)
	requireNoSecretLeak(t, err, "stored-refresh-token")
	requireNoSecretLeak(t, err, "stored-access-token")
}

func Test_bearerTokenScoperImpl_GetToken_InvalidStoredOAuthToken(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `not-json`)

	scoper := NewBearerTokenScoper(config, singleClient(http.DefaultClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	var syntaxErr *json.SyntaxError
	assert.ErrorAs(t, err, &syntaxErr)
	assert.Equal(t, "stored oauth token is corrupt", catalogErrorOf(t, err).Detail)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_EmptyStoredAccessAndRefreshTokenReturnsCatalogError(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"token_type":"Bearer"}`)

	scoper := NewBearerTokenScoper(config, singleClient(http.DefaultClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	assert.Equal(t, "no user authentication is available", catalogErrorOf(t, err).Detail)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_MalformedAuthorizationHeaderReturnsCatalogError(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"a b","token_type":"Bearer"}`)

	scoper := NewBearerTokenScoper(config, singleClient(http.DefaultClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	assert.Equal(t, "authorization header has an unexpected format", catalogErrorOf(t, err).Detail)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_CorruptStoredOAuthTokenLeaksNoSecret(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"stored-access-token","refresh_token":"stored-refresh-token",`)

	scoper := NewBearerTokenScoper(config, singleClient(http.DefaultClient))
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, snyk.NewUnauthorisedError("").ErrorCode)
	assert.Empty(t, token)
	requireNoSecretLeak(t, err, "stored-access-token")
	requireNoSecretLeak(t, err, "stored-refresh-token")
}

func Test_bearerTokenScoperImpl_RevokeToken_NotImplemented(t *testing.T) {
	scoper := NewBearerTokenScoper(configuration.NewWithOpts(), singleClient(http.DefaultClient))

	err := scoper.RevokeToken(context.Background(), "scoped-token")

	requireCatalogError(t, err, snyk.NewNotImplementedError("").ErrorCode)
}
