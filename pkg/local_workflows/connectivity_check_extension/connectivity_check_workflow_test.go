package workflows

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension/connectivity"
	"github.com/snyk/go-application-framework/pkg/networking"
)

func TestProxyDetectionWithNetworkAccess(t *testing.T) {
	// Set proxy environment variables using t.Setenv (automatic cleanup)
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
	t.Setenv("HTTP_PROXY", "http://proxy.example.com:3128")

	// Create configuration
	config := configuration.New()

	// Create NetworkAccess - it should automatically pick up proxy from environment
	networkAccess := networking.NewNetworkAccess(config)

	// Get the HTTP client
	httpClient := networkAccess.GetHttpClient()

	// Verify the client has the proper transport configured
	if httpClient.Transport == nil {
		t.Error("Expected HTTP client to have a transport configured")
	}

	// Create checker
	logger := zerolog.Nop()
	checker := connectivity.NewChecker(networkAccess, &logger, config)

	// Test proxy detection
	proxyConfig := checker.DetectProxyConfig()
	if !proxyConfig.Detected {
		t.Error("Expected proxy to be detected")
	}
	if proxyConfig.URL != "http://proxy.example.com:8080" {
		t.Errorf("Expected proxy URL to be http://proxy.example.com:8080, got %s", proxyConfig.URL)
	}
	if proxyConfig.Variable != "HTTPS_PROXY" {
		t.Errorf("Expected proxy variable to be HTTPS_PROXY, got %s", proxyConfig.Variable)
	}
}

func TestJSONOutputWithOrganizations(t *testing.T) {
	// Create test server that returns organizations
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/rest/orgs") {
			// Return mock organizations
			response := `{
				"data": [
					{
						"id": "test-org-1",
						"attributes": {
							"name": "Test Organization",
							"slug": "test-org",
							"group_id": "test-group-id"
						},
						"relationships": {}
					}
				]
			}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(response)); err != nil {
				t.Logf("Failed to write response: %v", err)
			}
		} else {
			// Default response for connectivity checks
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Create configuration with token
	config := configuration.New()
	config.Set("insecure", true)
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	config.Set(configuration.API_URL, server.URL)
	config.Set("json", true) // Request JSON output

	// Create NetworkAccess
	networkAccess := networking.NewNetworkAccess(config)

	// Create a logger
	logger := zerolog.Nop()

	// Override SnykHosts for testing
	cleanup := connectivity.SetSnykHostsForTesting([]string{server.URL[8:]})
	defer cleanup()

	// Create checker
	checker := connectivity.NewChecker(networkAccess, &logger, config)

	// Run connectivity check
	result, err := checker.CheckConnectivity()
	if err != nil {
		t.Fatalf("Connectivity check failed: %v", err)
	}

	// Verify token is detected
	if !result.TokenPresent {
		t.Error("Expected token to be present")
	}

	// Verify organizations were fetched
	if len(result.Organizations) != 1 {
		t.Errorf("Expected 1 organization, got %d", len(result.Organizations))
	}

	if len(result.Organizations) > 0 {
		org := result.Organizations[0]
		if org.ID != "test-org-1" {
			t.Errorf("Expected org ID 'test-org-1', got '%s'", org.ID)
		}
		if org.Name != "Test Organization" {
			t.Errorf("Expected org name 'Test Organization', got '%s'", org.Name)
		}
		// Note: We don't check IsDefault here because this test doesn't mock GetDefaultOrgId()
	}

	// Test JSON marshaling
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	// Verify JSON contains organizations
	var jsonResult map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonResult); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	orgs, ok := jsonResult["organizations"].([]interface{})
	if !ok || len(orgs) == 0 {
		t.Error("Expected organizations in JSON output")
	}
}
