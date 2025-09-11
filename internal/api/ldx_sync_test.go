package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLdxSyncConfig(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		assert.Equal(t, "/rest/ldx_sync/config", r.URL.Path)
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))
		assert.Equal(t, "https://github.com/test/repo.git", r.URL.Query().Get("remote_url"))

		// Return mock response
		response := LdxSyncResponse{
			Data: LdxSyncConfig{
				ID:   "3fa85f64-5717-4562-b3fc-2c963f66afa6",
				Type: "config",
				Attributes: LdxSyncAttributes{
					Scope:          "global",
					LastModifiedAt: "2024-01-15T10:30:00Z",
					ConfigData: LdxSyncConfigData{
						AuthenticationMethod: "oauth",
						Endpoints: LdxSyncEndpoints{
							APIEndpoint:  "https://api.snyk.io",
							CodeEndpoint: "https://deeproxy.snyk.io",
						},
						Organizations: []LdxSyncOrganization{
							{
								ID:   "test-org-123",
								Name: "Test Organization",
								Slug: "test-org",
							},
						},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test mock response, error handling not needed
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create API client
	client := &snykApiClient{
		url:    server.URL,
		client: http.DefaultClient,
	}

	// Test GetLdxSyncConfig
	config, err := client.GetLdxSyncConfig("https://github.com/test/repo.git")
	assert.NoError(t, err)
	assert.Equal(t, "3fa85f64-5717-4562-b3fc-2c963f66afa6", config.ID)
	assert.Equal(t, "config", config.Type)
	assert.Equal(t, "global", config.Attributes.Scope)
	assert.Equal(t, "oauth", config.Attributes.ConfigData.AuthenticationMethod)
	assert.Equal(t, "https://api.snyk.io", config.Attributes.ConfigData.Endpoints.APIEndpoint)
	assert.Equal(t, "https://deeproxy.snyk.io", config.Attributes.ConfigData.Endpoints.CodeEndpoint)
	assert.Len(t, config.Attributes.ConfigData.Organizations, 1)
	assert.Equal(t, "test-org-123", config.Attributes.ConfigData.Organizations[0].ID)
	assert.Equal(t, "Test Organization", config.Attributes.ConfigData.Organizations[0].Name)
	assert.Equal(t, "test-org", config.Attributes.ConfigData.Organizations[0].Slug)
}

func TestGetLdxSyncConfig_EmptyOrganizations(t *testing.T) {
	// Create a mock server that returns empty organizations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := LdxSyncResponse{
			Data: LdxSyncConfig{
				ID:   "3fa85f64-5717-4562-b3fc-2c963f66afa6",
				Type: "config",
				Attributes: LdxSyncAttributes{
					Scope:          "global",
					LastModifiedAt: "2024-01-15T10:30:00Z",
					ConfigData: LdxSyncConfigData{
						AuthenticationMethod: "oauth",
						Endpoints: LdxSyncEndpoints{
							APIEndpoint:  "https://api.snyk.io",
							CodeEndpoint: "https://deeproxy.snyk.io",
						},
						Organizations: []LdxSyncOrganization{}, // Empty organizations
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test mock response, error handling not needed
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create API client
	client := &snykApiClient{
		url:    server.URL,
		client: http.DefaultClient,
	}

	// Test GetLdxSyncConfig should return config but with empty organizations
	config, err := client.GetLdxSyncConfig("https://github.com/test/repo.git")
	assert.NoError(t, err)
	assert.Len(t, config.Attributes.ConfigData.Organizations, 0)
}

func TestGetLdxSyncConfig_HTTPError(t *testing.T) {
	// Create a mock server that returns HTTP error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create API client
	client := &snykApiClient{
		url:    server.URL,
		client: http.DefaultClient,
	}

	// Test GetLdxSyncConfig should return error
	_, err := client.GetLdxSyncConfig("https://github.com/test/repo.git")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed")
}

func TestGetLdxSyncConfig_InvalidJSON(t *testing.T) {
	// Create a mock server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck // test mock response, error handling not needed
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	// Create API client
	client := &snykApiClient{
		url:    server.URL,
		client: http.DefaultClient,
	}

	// Test GetLdxSyncConfig should return error
	_, err := client.GetLdxSyncConfig("https://github.com/test/repo.git")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse LDX-Sync response")
}
