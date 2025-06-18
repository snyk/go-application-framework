package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	t.Run("Bad URL", func(t *testing.T) {
		_, err := DeriveEndpointFromPAT("empty_pat", config, client, []string{"https://someRandomUrl.com"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Authentication error")
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
}

func TestExtractClaimsFromPAT(t *testing.T) {
	t.Run("Valid PAT with all claims", func(t *testing.T) {
		payload := `{"j":"pat-id-123","s":"sub-id-456","e":1678886400,"h":"api.snyk.io"}`
		pat := createMockPAT(t, payload)

		claims, err := ExtractClaimsFromPAT(pat)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "pat-id-123", claims.JWTID)
		assert.Equal(t, "sub-id-456", claims.Subject)
		assert.Equal(t, int64(1678886400), claims.Expiration)
		assert.Equal(t, "api.snyk.io", claims.Hostname)
	})

	t.Run("Valid PAT with some claims missing", func(t *testing.T) {
		payload := `{"j":"pat-id-123","h":"api.snyk.io"}`
		pat := createMockPAT(t, payload)

		claims, err := ExtractClaimsFromPAT(pat)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "pat-id-123", claims.JWTID)
		assert.Empty(t, claims.Subject)
		assert.Zero(t, claims.Expiration)
		assert.Equal(t, "api.snyk.io", claims.Hostname)
	})

	t.Run("PAT with fewer than 4 segments", func(t *testing.T) {
		pat := "snyk_test.12345678.payload"
		claims, err := ExtractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid number of segments: 3")
		assert.Nil(t, claims)
	})

	t.Run("PAT with more than 4 segments", func(t *testing.T) {
		pat := "snyk_test.12345678.payload.signature.extra"
		claims, err := ExtractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid number of segments: 5")
		assert.Nil(t, claims)
	})

	t.Run("PAT with invalid base64 payload", func(t *testing.T) {
		pat := "snyk_test.12345678.invalid-base64!@#$.signature"
		claims, err := ExtractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode payload")
		assert.Nil(t, claims)
	})

	t.Run("PAT with invalid JSON payload", func(t *testing.T) {
		payload := `{"j":"pat-id-123", "h":"api.snyk.io", "e":1678886400, "s":"sub-id-456`
		pat := createMockPAT(t, payload)

		claims, err := ExtractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal payload")
		assert.Nil(t, claims)
	})
}

func createMockPAT(t *testing.T, payload string) string {
	t.Helper()

	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := "signature"
	return fmt.Sprintf("snyk_test.12345678.%s.%s", encodedPayload, signature)
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
