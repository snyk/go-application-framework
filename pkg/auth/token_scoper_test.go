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
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.PostForm.Get("grant_type"))
		assert.Equal(t, subjectToken, r.PostForm.Get("subject_token"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", r.PostForm.Get("subject_token_type"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", r.PostForm.Get("requested_token_type"))
		assert.Equal(t, "org.read org.project.read", r.PostForm.Get("scope"))
		assert.Equal(t, "3600", r.PostForm.Get("ttl"))
		assert.Equal(t, "test-client-id", r.PostForm.Get("client_id"))
		assert.Equal(t, "test-client-secret", r.PostForm.Get("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + scopedToken + `","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"bearer","expires_in":2874,"scope":"org.read org.project.read"}`))
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, subjectToken)
	config.Set(PARAMETER_CLIENT_ID, "test-client-id")
	config.Set(PARAMETER_CLIENT_SECRET, "test-client-secret")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read", "org.project.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, scopedToken, token)
}

func Test_bearerTokenScoperImpl_GetToken_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
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

func Test_bearerTokenScoperImpl_GetToken_FallsBackToOAuthClientID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, OAUTH_CLIENT_ID, r.PostForm.Get("client_id"))
		assert.Empty(t, r.PostForm.Get("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"scoped-token","token_type":"bearer","expires_in":2874}`))
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "subject-token")

	scoper := NewBearerTokenScoper(config, server.Client())
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.NoError(t, err)
	assert.Equal(t, "scoped-token", token)
}

func Test_bearerTokenScoperImpl_GetToken_NoUserAuthentication(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.example.invalid")

	scoper := NewBearerTokenScoper(config, http.DefaultClient)
	token, err := scoper.GetToken(context.Background(), []string{"org.read"}, time.Hour)

	require.Error(t, err)
	assert.Empty(t, token)
}
