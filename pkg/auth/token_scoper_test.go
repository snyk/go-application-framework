package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func Test_bearerTokenScoperImpl_GetToken_NoUserAuthentication(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")

	scoper := NewBearerTokenScoper(config, http.DefaultClient)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Error(t, err)
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

	require.Error(t, err)
	assert.Empty(t, token)
}
