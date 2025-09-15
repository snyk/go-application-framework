package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
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
		oauth := v20241015.Oauth
		response := v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Id:   uuid.New(),
				Type: v20241015.ConfigResourceTypeConfig,
				Attributes: v20241015.ConfigAttributes{
					Scope:          v20241015.Global,
					LastModifiedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
					ConfigData: v20241015.ConfigData{
						AuthenticationMethod: &oauth,
						Endpoints: &v20241015.Endpoints{
							ApiEndpoint:  &[]string{"https://api.snyk.io"}[0],
							CodeEndpoint: &[]string{"https://deeproxy.snyk.io"}[0],
						},
						Organizations: &[]v20241015.Organization{
							{
								Id:   "test-org-123",
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
	assert.NotEmpty(t, config.Data.Id)
	assert.Equal(t, v20241015.ConfigResourceTypeConfig, config.Data.Type)
	assert.Equal(t, v20241015.Global, config.Data.Attributes.Scope)
	assert.Equal(t, v20241015.Oauth, *config.Data.Attributes.ConfigData.AuthenticationMethod)
	assert.Equal(t, "https://api.snyk.io", *config.Data.Attributes.ConfigData.Endpoints.ApiEndpoint)
	assert.Equal(t, "https://deeproxy.snyk.io", *config.Data.Attributes.ConfigData.Endpoints.CodeEndpoint)
	assert.Len(t, *config.Data.Attributes.ConfigData.Organizations, 1)
	assert.Equal(t, "test-org-123", (*config.Data.Attributes.ConfigData.Organizations)[0].Id)
	assert.Equal(t, "Test Organization", (*config.Data.Attributes.ConfigData.Organizations)[0].Name)
	assert.Equal(t, "test-org", (*config.Data.Attributes.ConfigData.Organizations)[0].Slug)
}

func TestGetLdxSyncConfig_EmptyOrganizations(t *testing.T) {
	// Create a mock server that returns empty organizations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauth := v20241015.Oauth
		response := v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Id:   uuid.New(),
				Type: v20241015.ConfigResourceTypeConfig,
				Attributes: v20241015.ConfigAttributes{
					Scope:          v20241015.Global,
					LastModifiedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
					ConfigData: v20241015.ConfigData{
						AuthenticationMethod: &oauth,
						Endpoints: &v20241015.Endpoints{
							ApiEndpoint:  &[]string{"https://api.snyk.io"}[0],
							CodeEndpoint: &[]string{"https://deeproxy.snyk.io"}[0],
						},
						Organizations: &[]v20241015.Organization{}, // Empty organizations
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
	assert.Len(t, *config.Data.Attributes.ConfigData.Organizations, 0)
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
