package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

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

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, subjectToken)

	scoper := NewBearerTokenScoper(config, server.Client())
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

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
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

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Error(t, err)
	assert.Empty(t, token)
}

func requireCatalogError(t *testing.T, err error, errorCode string) {
	t.Helper()
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	require.Equal(t, errorCode, catalogErr.ErrorCode)
}

func Test_bearerTokenScoperImpl_GetToken_NetworkFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-CLI-0022")
	assert.Empty(t, token)
}

func requireExchangeStatusError(t *testing.T, status int, errorCode string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, err := w.Write([]byte(`{"error":"server_said_no"}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Empty(t, token)
	requireCatalogError(t, err, errorCode)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Contains(t, catalogErr.Detail, strconv.Itoa(status))
	assert.Equal(t, `{"error":"server_said_no"}`, catalogErr.Meta["body"])
}

func Test_bearerTokenScoperImpl_GetToken_Unauthorized(t *testing.T) {
	requireExchangeStatusError(t, http.StatusUnauthorized, "SNYK-0005")
}

func Test_bearerTokenScoperImpl_GetToken_BadRequest(t *testing.T) {
	requireExchangeStatusError(t, http.StatusBadRequest, "SNYK-0003")
}

func Test_bearerTokenScoperImpl_GetToken_TooManyRequests(t *testing.T) {
	requireExchangeStatusError(t, http.StatusTooManyRequests, "SNYK-0001")
}

func Test_bearerTokenScoperImpl_GetToken_BadGateway(t *testing.T) {
	requireExchangeStatusError(t, http.StatusBadGateway, "SNYK-0008")
}

func Test_bearerTokenScoperImpl_GetToken_ServiceUnavailable(t *testing.T) {
	requireExchangeStatusError(t, http.StatusServiceUnavailable, "SNYK-0009")
}

func Test_bearerTokenScoperImpl_GetToken_Forbidden(t *testing.T) {
	requireExchangeStatusError(t, http.StatusForbidden, "SNYK-0005")
}

func Test_bearerTokenScoperImpl_GetToken_InternalServerError(t *testing.T) {
	requireExchangeStatusError(t, http.StatusInternalServerError, "SNYK-9999")
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

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, httpClient)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-CLI-0022")
	assert.ErrorIs(t, err, sentinel)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_NoUserAuthentication(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")

	scoper := NewBearerTokenScoper(config, http.DefaultClient)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-CLI-0006")
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"token_type":"bearer","expires_in":2874}`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-9999")
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_MalformedResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`not-json`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-9999")
	assert.NotNil(t, errors.Unwrap(err))
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_DecodeFailureKeepsCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`not-json`))
		assert.NoError(t, err)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-9999")
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

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-9999")
	assert.NotNil(t, errors.Unwrap(err))
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

	scoper := NewBearerTokenScoper(config, server.Client())
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

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
	assert.Contains(t, config.GetString(CONFIG_KEY_OAUTH_TOKEN), "refreshed-access-token")
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

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-0005")
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_GetToken_InvalidStoredOAuthToken(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")
	config.Set(CONFIG_KEY_OAUTH_TOKEN, `not-json`)

	scoper := NewBearerTokenScoper(config, http.DefaultClient)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	requireCatalogError(t, err, "SNYK-0005")
	var syntaxErr *json.SyntaxError
	assert.ErrorAs(t, err, &syntaxErr)
	assert.Empty(t, token)
}

func Test_bearerTokenScoperImpl_RevokeToken_NotImplemented(t *testing.T) {
	scoper := NewBearerTokenScoper(configuration.NewWithOpts(), http.DefaultClient)

	err := scoper.RevokeToken(context.Background(), "scoped-token")

	requireCatalogError(t, err, "SNYK-0002")
}
