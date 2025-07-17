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

func TestConnectivityCheckerWithRealNetworkAccess(t *testing.T) {
	// Create a test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate different responses based on the request
		switch {
		case strings.Contains(r.URL.Path, "api.snyk.io"):
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "app.snyk.io"):
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "forbidden"):
			w.WriteHeader(http.StatusForbidden)
		case strings.Contains(r.URL.Path, "timeout"):
			// Simulate timeout by not responding
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create real configuration
	config := configuration.New()
	config.Set("insecure", true) // Allow insecure connections for test server

	// Create real NetworkAccess from go-application-framework
	networkAccess := networking.NewNetworkAccess(config)

	// Create a logger
	logger := zerolog.Nop()

	// Override SnykHosts for testing with our test server
	cleanup := connectivity.SetSnykHostsForTesting([]string{
		server.URL[8:] + "/api.snyk.io",
		server.URL[8:] + "/app.snyk.io",
		server.URL[8:] + "/forbidden",
	})
	defer cleanup()

	// Create checker with real network access
	checker := connectivity.NewChecker(networkAccess, &logger, config)

	// Run connectivity check
	result, err := checker.CheckConnectivity()
	if err != nil {
		t.Fatalf("Connectivity check failed: %v", err)
	}

	// Verify results
	if len(result.HostResults) != 3 {
		t.Errorf("Expected 3 host results, got %d", len(result.HostResults))
	}

	// Check specific responses using helper function
	for _, hostResult := range result.HostResults {
		verifyHostResult(t, hostResult)
	}
}

// Helper function to verify host results and reduce cyclomatic complexity
func verifyHostResult(t *testing.T, hostResult connectivity.HostResult) {
	t.Helper()

	switch {
	case strings.Contains(hostResult.URL, "api.snyk.io"):
		if hostResult.StatusCode != http.StatusOK {
			t.Errorf("Expected OK status for api.snyk.io, got %d", hostResult.StatusCode)
		}
		if hostResult.Status != connectivity.StatusOK {
			t.Errorf("Expected StatusOK for api.snyk.io, got %v", hostResult.Status)
		}
	case strings.Contains(hostResult.URL, "app.snyk.io"):
		if hostResult.StatusCode != http.StatusNoContent {
			t.Errorf("Expected NoContent status for app.snyk.io, got %d", hostResult.StatusCode)
		}
		if hostResult.Status != connectivity.StatusOK {
			t.Errorf("Expected StatusOK for app.snyk.io, got %v", hostResult.Status)
		}
	case strings.Contains(hostResult.URL, "forbidden"):
		if hostResult.StatusCode != http.StatusForbidden {
			t.Errorf("Expected Forbidden status for forbidden endpoint, got %d", hostResult.StatusCode)
		}
		if hostResult.Status != connectivity.StatusReachable {
			t.Errorf("Expected StatusReachable for forbidden endpoint, got %v", hostResult.Status)
		}
	}
}

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

func TestNetworkAccessWithCustomHeaders(t *testing.T) {
	// Create test server that checks for custom header
	expectedHeader := "X-Custom-Header"
	expectedValue := "test-value"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(expectedHeader) == expectedValue {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	// Create configuration
	config := configuration.New()
	config.Set("insecure", true)

	// Create NetworkAccess
	networkAccess := networking.NewNetworkAccess(config)

	// Add custom header
	networkAccess.AddHeaderField(expectedHeader, expectedValue)

	// Create checker
	logger := zerolog.Nop()
	checker := connectivity.NewChecker(networkAccess, &logger, config)

	// Override hosts for testing
	cleanup := connectivity.SetSnykHostsForTesting([]string{server.URL[8:]})
	defer cleanup()

	// Run check
	result, err := checker.CheckConnectivity()
	if err != nil {
		t.Fatalf("Connectivity check failed: %v", err)
	}

	// Verify the header was sent
	if len(result.HostResults) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(result.HostResults))
	}

	if result.HostResults[0].StatusCode != http.StatusOK {
		t.Errorf("Expected OK status (header was sent), got %d", result.HostResults[0].StatusCode)
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
							"slug": "test-org"
						},
						"relationships": {
							"group": {
								"data": {
									"id": "test-group"
								}
							}
						}
					}
				],
				"included": [
					{
						"id": "test-group",
						"type": "group",
						"attributes": {
							"name": "Test Group"
						}
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
		if org.Slug != "test-org" {
			t.Errorf("Expected org slug 'test-org', got '%s'", org.Slug)
		}
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
