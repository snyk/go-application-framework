package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestIsAuthTypeToken(t *testing.T) {
	assert.True(t, IsAuthTypeToken("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
	assert.False(t, IsAuthTypeToken("not-a-uuid"))
}

func TestIsAuthTypePAT(t *testing.T) {
	assert.True(t, IsAuthTypePAT("snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"))
	assert.False(t, IsAuthTypePAT("invalid-pat"))
}

func TestDeriveEndpointFromPAT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hidden/self/personal_access_token/metadata" {
			w.Header().Set("Content-Type", "application/vnd.api+json")
			if r.Header.Get("Authorization") == "token valid_pat" {
				w.WriteHeader(http.StatusOK)
				resBody := `{"jsonapi":{"version":"1.0"},"data":{"attributes":{"hostname":"snyk.io"},"id":"someRandomId","type":"personal_access_token"},"links":{}}`
				//nolint:errcheck // not needed for testing
				_, _ = w.Write([]byte(resBody))
				return
			} else if r.Header.Get("Authorization") == "token valid_eu_pat" {
				w.WriteHeader(http.StatusOK)
				resBody := `{"jsonapi":{"version":"1.0"},"data":{"attributes":{"hostname":"eu.snyk.io"},"id":"someRandomId","type":"personal_access_token"},"links":{}}`
				//nolint:errcheck // not needed for testing
				_, _ = w.Write([]byte(resBody))
				return
			} else if r.Header.Get("Authorization") == "token invalid_pat" {
				w.WriteHeader(http.StatusOK)
				resBody := `{"jsonapi":{"version":"1.0"},"data":{"attributes":{"hostname":"invalid.hostname.io"},"id":"someRandomId","type":"personal_access_token"},"links":{}}`
				//nolint:errcheck // not needed for testing
				_, _ = w.Write([]byte(resBody))
				return
			} else if r.Header.Get("Authorization") == "token empty_pat" {
				w.WriteHeader(http.StatusOK)
				resBody := `{"jsonapi":{"version":"1.0"},"data":{"attributes":{"hostname":""},"id":"someRandomId","type":"personal_access_token"},"links":{}}`
				//nolint:errcheck // not needed for testing
				_, _ = w.Write([]byte(resBody))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_ALLOWED_HOST_REGEXP, `^api(\.(.+))?\.snyk\.io$`)
	client := server.Client()

	t.Run("Valid PAT", func(t *testing.T) {
		endpoint, err := DeriveEndpointFromPAT("valid_pat", config, client, server.URL)
		assert.NoError(t, err)
		assert.Equal(t, "https://api.snyk.io", endpoint)
	})

	t.Run("Valid EU PAT", func(t *testing.T) {
		endpoint, err := DeriveEndpointFromPAT("valid_eu_pat", config, client, server.URL)
		assert.NoError(t, err)
		assert.Equal(t, "https://api.eu.snyk.io", endpoint)
	})

	t.Run("Unauthorized PAT", func(t *testing.T) {
		_, err := DeriveEndpointFromPAT("invalid_pat", config, client, server.URL)
		expectedError := "invalid hostname: api.invalid.hostname.io"
		assert.EqualError(t, err, expectedError)
	})

	t.Run("Cached PAT - should not call server", func(t *testing.T) {
		cachedPATKey := GetCachedPatKeyname("cached_pat")
		config.Set(cachedPATKey, "https://api.cached.snyk.io")

		endpoint, err := DeriveEndpointFromPAT("cached_pat", config, client, server.URL)
		assert.NoError(t, err)
		assert.Equal(t, "https://api.cached.snyk.io", endpoint)
	})

	t.Run("Empty Hostname in Response", func(t *testing.T) {
		_, err := DeriveEndpointFromPAT("empty_pat", config, client, server.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid empty hostname")
	})
}

func TestGetCachedPatKeyname(t *testing.T) {
	assert.Equal(t, "cached_pat_test-token", GetCachedPatKeyname("test-token"))
}
