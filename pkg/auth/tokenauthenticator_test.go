package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	pat "github.com/snyk/go-application-framework/internal/api/personal_access_tokens/2024-03-19"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestIsAuthTypeToken(t *testing.T) {
	assert.True(t, IsAuthTypeToken("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
	// PAT format
	assert.False(t, IsAuthTypeToken("snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"))
}

func TestIsAuthTypePAT(t *testing.T) {
	assert.True(t, IsAuthTypePAT("snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"))
	// legacy token format
	assert.False(t, IsAuthTypePAT("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
}

func TestDeriveEndpointFromPAT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hidden/self/personal_access_token/metadata" {
			w.Header().Set("Content-Type", "application/vnd.api+json")
			hostname := ""
			w.WriteHeader(http.StatusOK)
			authorization := r.Header.Get("Authorization")

			if authorization == "token valid_pat" {
				hostname = "api.snyk.io"
			} else if authorization == "token valid_eu_pat" {
				hostname = "api.eu.snyk.io"
			} else if authorization == "token invalid_pat" {
				hostname = "invalid.hostname.io"
			} else if authorization == "token empty_pat" {
				hostname = ""
			}

			res := createPatMetadataReponse(t, hostname)
			err := json.NewEncoder(w).Encode(res.ApplicationvndApiJSON200)
			assert.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := configuration.NewWithOpts()
	config.Set(CONFIG_KEY_ALLOWED_HOST_REGEXP, `^api(\.(.+))?\.snyk\.io$`)
	client := server.Client()

	t.Run("Valid PAT", func(t *testing.T) {
		endpoint, err := DeriveEndpointFromPAT("valid_pat", config, client, []string{server.URL})
		assert.NoError(t, err)
		assert.Equal(t, "https://api.snyk.io", endpoint)
	})

	t.Run("Multiple regions", func(t *testing.T) {
		endpoint, err := DeriveEndpointFromPAT("valid_pat", config, client, []string{"https://someRandomUrl.com", server.URL, "https://someOtherRandomUrl.com"})
		assert.NoError(t, err)
		assert.Equal(t, "https://api.snyk.io", endpoint)
	})

	t.Run("Valid EU PAT", func(t *testing.T) {
		endpoint, err := DeriveEndpointFromPAT("valid_eu_pat", config, client, []string{server.URL})
		assert.NoError(t, err)
		assert.Equal(t, "https://api.eu.snyk.io", endpoint)
	})

	t.Run("Unauthorized PAT", func(t *testing.T) {
		_, err := DeriveEndpointFromPAT("invalid_pat", config, client, []string{server.URL})
		expectedError := "invalid hostname: api.invalid.hostname.io"
		assert.ErrorContains(t, err, expectedError)
	})

	t.Run("Empty Hostname in Response", func(t *testing.T) {
		_, err := DeriveEndpointFromPAT("empty_pat", config, client, []string{server.URL})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid empty hostname")
	})

	t.Run("Bad URL", func(t *testing.T) {
		_, err := DeriveEndpointFromPAT("empty_pat", config, client, []string{"https://someRandomUrl.com"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Authentication error")
	})
}

func createPatMetadataReponse(t *testing.T, hostname string) *pat.GetPatMetadataResponse {
	t.Helper()

	id := "someRandomId"
	return &pat.GetPatMetadataResponse{
		Body:         []byte{},
		HTTPResponse: nil,
		ApplicationvndApiJSON200: &struct {
			Data struct {
				Attributes struct {
					Hostname *string `json:"hostname,omitempty"`
				} `json:"attributes"`
				Id   pat.PatId   `json:"id"`
				Type pat.PatType `json:"type"`
			} `json:"data"`
			Jsonapi *pat.JsonApi  `json:"jsonapi,omitempty"`
			Links   *pat.SelfLink `json:"links,omitempty"`
		}{
			Data: struct {
				Attributes struct {
					Hostname *string `json:"hostname,omitempty"`
				} `json:"attributes"`
				Id   pat.PatId   `json:"id"`
				Type pat.PatType `json:"type"`
			}{
				Attributes: struct {
					Hostname *string `json:"hostname,omitempty"`
				}{
					Hostname: &hostname,
				},
				Id:   id,
				Type: pat.PersonalAccessToken,
			},
			Jsonapi: &pat.JsonApi{
				Version: "1.0",
			},
			Links: &pat.SelfLink{
				Self: &pat.LinkProperty{},
			},
		},
	}
}
