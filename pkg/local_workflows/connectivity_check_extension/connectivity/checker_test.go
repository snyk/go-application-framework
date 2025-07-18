package connectivity

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api/contract"
	internalmocks "github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

// createTestChecker is a helper to create a Checker with mocked dependencies
func createTestChecker(t *testing.T, ctrl *gomock.Controller, config configuration.Configuration) (*Checker, *mocks.MockNetworkAccess) {
	t.Helper()
	mockNA := mocks.NewMockNetworkAccess(ctrl)
	logger := zerolog.Nop()

	// Expect GetHttpClient to be called for API client initialization
	mockNA.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()

	checker := NewChecker(mockNA, &logger, config)
	return checker, mockNA
}

func TestNewChecker(t *testing.T) {
	// Create mock NetworkAccess
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNA := mocks.NewMockNetworkAccess(ctrl)
	logger := zerolog.Nop()
	config := configuration.New()

	// Expect GetHttpClient to be called for API client initialization
	mockNA.EXPECT().GetHttpClient().Return(&http.Client{})

	// Create checker
	checker := NewChecker(mockNA, &logger, config)

	// Verify checker is created correctly
	if checker == nil {
		t.Fatal("Expected NewChecker to return a checker, got nil")
	}
	if checker.networkAccess != mockNA {
		t.Error("Expected checker to have the provided NetworkAccess")
	}
	if checker.logger != &logger {
		t.Error("Expected checker to have the provided logger")
	}
	if checker.config != config {
		t.Error("Expected checker to have the provided configuration")
	}
	if checker.timeout != 10*time.Second {
		t.Errorf("Expected default timeout to be 10s, got %v", checker.timeout)
	}
	if checker.apiClient == nil {
		t.Error("Expected checker to have an API client")
	}
}

func TestDetectProxyConfig(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected ProxyConfig
	}{
		{
			name: "HTTPS_PROXY set",
			envVars: map[string]string{
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:8080",
				Variable: "HTTPS_PROXY",
			},
		},
		{
			name: "HTTP_PROXY fallback",
			envVars: map[string]string{
				"HTTP_PROXY": "http://proxy.example.com:3128",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:3128",
				Variable: "HTTP_PROXY",
			},
		},
		{
			name:     "No proxy set",
			envVars:  map[string]string{},
			expected: ProxyConfig{Detected: false},
		},
		{
			name: "NO_PROXY set",
			envVars: map[string]string{
				"HTTPS_PROXY": "http://proxy.example.com:8080",
				"NO_PROXY":    "localhost,127.0.0.1",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:8080",
				Variable: "HTTPS_PROXY",
				NoProxy:  "localhost,127.0.0.1",
			},
		},
		{
			name: "Priority order - HTTPS_PROXY wins",
			envVars: map[string]string{
				"HTTPS_PROXY": "http://secure-proxy.example.com:8080",
				"HTTP_PROXY":  "http://proxy.example.com:3128",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://secure-proxy.example.com:8080",
				Variable: "HTTPS_PROXY",
			},
		},
		{
			name: "lowercase no_proxy used",
			envVars: map[string]string{
				"HTTPS_PROXY": "http://proxy.example.com:8080",
				"no_proxy":    "*.local,169.254.0.0/16",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:8080",
				Variable: "HTTPS_PROXY",
				NoProxy:  "*.local,169.254.0.0/16",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all proxy-related environment variables for test isolation
			proxyEnvVars := []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}
			for _, key := range proxyEnvVars {
				t.Setenv(key, "")
			}

			// Set test environment
			for key, val := range tt.envVars {
				t.Setenv(key, val)
			}

			// Create test checker
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			config := configuration.New()
			checker, _ := createTestChecker(t, ctrl, config)

			// Test proxy detection
			result := checker.DetectProxyConfig()

			// Verify results
			if result.Detected != tt.expected.Detected {
				t.Errorf("Expected Detected=%v, got %v", tt.expected.Detected, result.Detected)
			}
			if result.URL != tt.expected.URL {
				t.Errorf("Expected URL=%s, got %s", tt.expected.URL, result.URL)
			}
			if result.Variable != tt.expected.Variable {
				t.Errorf("Expected Variable=%s, got %s", tt.expected.Variable, result.Variable)
			}
			if result.NoProxy != tt.expected.NoProxy {
				t.Errorf("Expected NoProxy=%s, got %s", tt.expected.NoProxy, result.NoProxy)
			}
		})
	}
}

func TestCheckHost(t *testing.T) {
	tests := []struct {
		name             string
		serverResponse   int
		serverHeader     map[string]string
		expectedStatus   ConnectionStatus
		expectedCategory string
		expectedAuth     string
	}{
		{
			name:           "OK response",
			serverResponse: http.StatusOK,
			expectedStatus: StatusOK,
		},
		{
			name:           "No content response",
			serverResponse: http.StatusNoContent,
			expectedStatus: StatusOK,
		},
		{
			name:           "Redirect response",
			serverResponse: http.StatusMovedPermanently,
			expectedStatus: StatusOK,
		},
		{
			name:           "Forbidden response",
			serverResponse: http.StatusForbidden,
			expectedStatus: StatusReachable,
		},
		{
			name:           "Not found response",
			serverResponse: http.StatusNotFound,
			expectedStatus: StatusReachable,
		},
		{
			name:           "Server error",
			serverResponse: http.StatusInternalServerError,
			expectedStatus: StatusServerError,
		},
		{
			name:           "Bad gateway",
			serverResponse: http.StatusBadGateway,
			expectedStatus: StatusServerError,
		},
		{
			name:           "Proxy auth required - Negotiate",
			serverResponse: http.StatusProxyAuthRequired,
			serverHeader: map[string]string{
				"Proxy-Authenticate": "Negotiate",
			},
			expectedStatus:   StatusProxyAuthSupported,
			expectedCategory: "proxy_auth",
			expectedAuth:     "Negotiate",
		},
		{
			name:           "Proxy auth required - Basic",
			serverResponse: http.StatusProxyAuthRequired,
			serverHeader: map[string]string{
				"Proxy-Authenticate": "Basic realm=\"Proxy\"",
			},
			expectedStatus:   StatusProxyAuthSupported,
			expectedCategory: "proxy_auth",
			expectedAuth:     "Basic realm=\"Proxy\"",
		},
		{
			name:           "Proxy auth required - Unsupported",
			serverResponse: http.StatusProxyAuthRequired,
			serverHeader: map[string]string{
				"Proxy-Authenticate": "Digest realm=\"Proxy\"",
			},
			expectedStatus:   StatusProxyAuthUnsupported,
			expectedCategory: "proxy_auth",
			expectedAuth:     "Digest realm=\"Proxy\"",
		},
		{
			name:           "Unauthorized",
			serverResponse: http.StatusUnauthorized,
			expectedStatus: StatusBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.serverHeader {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.serverResponse)
			}))
			defer server.Close()

			// Create test setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			config := configuration.New()
			checker, mockNA := createTestChecker(t, ctrl, config)

			// Set up mock expectations for checkHost
			mockNA.EXPECT().GetUnauthorizedHttpClient().Return(server.Client())

			// Parse server URL to get host
			serverURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("Failed to parse server URL: %v", err)
			}
			host := serverURL.Host

			// Test checkHost
			result := checker.checkHost(host)

			// Verify results
			if result.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, result.Status)
			}
			if tt.expectedAuth != "" && result.ProxyAuth != tt.expectedAuth {
				t.Errorf("Expected proxy auth %v, got %v", tt.expectedAuth, result.ProxyAuth)
			}
		})
	}
}

func TestCheckHost_WithPath(t *testing.T) {
	tests := []struct {
		host         string
		expectedPath string
	}{
		{
			host:         "api.snyk.io",
			expectedPath: "/",
		},
		{
			host:         "deeproxy.snyk.io/filters",
			expectedPath: "/filters",
		},
		{
			host:         "downloads.snyk.io:443/cli/wasm/bundle.tar.gz",
			expectedPath: "/cli/wasm/bundle.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			requestPath := ""
			// Create test server that captures the request path
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Create test setup
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			config := configuration.New()
			checker, mockNA := createTestChecker(t, ctrl, config)

			// Get server host/port
			serverURL, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("Failed to parse server URL: %v", err)
			}

			// For this test, we need to map the test host to our test server
			// Since we can't actually hit the real hosts
			testHost := serverURL.Host
			if strings.Contains(tt.host, "/") {
				// Keep the path part
				parts := strings.SplitN(tt.host, "/", 2)
				testHost = serverURL.Host + "/" + parts[1]
			} else if strings.Contains(tt.host, ":") && strings.Contains(tt.host, ".tar.gz") {
				// Special case for downloads with port and path
				testHost = serverURL.Host + "/cli/wasm/bundle.tar.gz"
			}

			// Set up mock expectations
			mockNA.EXPECT().GetUnauthorizedHttpClient().Return(server.Client())

			// Test checkHost
			result := checker.checkHost(testHost)

			// Verify the request path was correct
			if requestPath != tt.expectedPath {
				t.Errorf("Expected request path %s, got %s", tt.expectedPath, requestPath)
			}
			if result.Status != StatusOK {
				t.Errorf("Expected status OK, got %v", result.Status)
			}
		})
	}
}

func TestCategorizeError(t *testing.T) {
	// Create test setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	config := configuration.New()
	checker, _ := createTestChecker(t, ctrl, config)

	tests := []struct {
		name           string
		err            error
		expectedStatus ConnectionStatus
	}{
		{
			name:           "DNS error - no such host",
			err:            &net.DNSError{Err: "no such host", IsNotFound: true},
			expectedStatus: StatusDNSError,
		},
		{
			name:           "TLS error - certificate invalid",
			err:            fmt.Errorf("tls: certificate is invalid"),
			expectedStatus: StatusTLSError,
		},
		{
			name:           "Certificate error",
			err:            fmt.Errorf("x509: certificate signed by unknown authority"),
			expectedStatus: StatusTLSError,
		},
		{
			name:           "Timeout error",
			err:            &timeoutError{},
			expectedStatus: StatusTimeout,
		},
		{
			name:           "Connection refused",
			err:            fmt.Errorf("connection refused"),
			expectedStatus: StatusBlocked,
		},
		{
			name:           "Network unreachable",
			err:            fmt.Errorf("network is unreachable"),
			expectedStatus: StatusBlocked,
		},
		{
			name:           "Generic error",
			err:            fmt.Errorf("some other error"),
			expectedStatus: StatusBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := checker.categorizeError(tt.err)
			if status != tt.expectedStatus {
				t.Errorf("Expected status %v for error '%v', got %v", tt.expectedStatus, tt.err, status)
			}
		})
	}
}

func TestGenerateTODOs(t *testing.T) {
	// Create test setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	config := configuration.New()
	checker, _ := createTestChecker(t, ctrl, config)

	tests := []struct {
		name         string
		hostResult   HostResult
		proxyConfig  ProxyConfig
		expectedTODO string
		expectedNil  bool
	}{
		{
			name: "DNS error",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusDNSError,
			},
			expectedTODO: "DNS resolution failed for 'api.snyk.io'",
		},
		{
			name: "TLS error",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusTLSError,
			},
			expectedTODO: "TLS/SSL error connecting to 'api.snyk.io'",
		},
		{
			name: "Timeout",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusTimeout,
			},
			expectedTODO: "Connection to 'api.snyk.io' timed out",
		},
		{
			name: "Blocked",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusBlocked,
			},
			expectedTODO: "Received HTTP status '0' when connecting to 'api.snyk.io'",
		},
		{
			name: "Server error",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusServerError,
				StatusCode:  500,
			},
			expectedTODO: "Server error (HTTP 500) when connecting to 'api.snyk.io'",
		},
		{
			name: "Proxy auth required with proxy config",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusProxyAuthSupported,
				ProxyAuth:   "Basic",
			},
			proxyConfig: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:8080",
			},
			expectedTODO: "Proxy requires 'Basic' authentication for 'api.snyk.io'",
		},
		{
			name: "OK status - no TODO",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusOK,
			},
			expectedNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ConnectivityCheckResult{
				ProxyConfig: tt.proxyConfig,
			}

			checker.generateTODOs(result, &tt.hostResult)

			if tt.expectedNil {
				if len(result.TODOs) > 0 {
					t.Errorf("Expected no TODOs, got %v", result.TODOs)
				}
			} else {
				if len(result.TODOs) == 0 {
					t.Fatal("Expected TODO to be generated")
				}
				// Check if expected TODO message is present
				found := false
				for _, todo := range result.TODOs {
					if strings.Contains(todo.Message, tt.expectedTODO) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected TODO containing '%s', got %v", tt.expectedTODO, result.TODOs)
				}
			}
		})
	}
}

func TestCheckConnectivity(t *testing.T) {
	// Create a test server that responds differently based on path
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.Host, "api.snyk.io"):
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.Host, "app.snyk.io"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	// Override SnykHosts for testing
	cleanup := SetSnykHostsForTesting([]string{
		"api.snyk.io",
		"app.snyk.io",
		"static.snyk.io",
	})
	defer cleanup()

	// Create checker with mock NetworkAccess
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNA := mocks.NewMockNetworkAccess(ctrl)
	// Set expectation for GetUnauthorizedHttpClient (used by checkHost)
	mockNA.EXPECT().GetUnauthorizedHttpClient().Return(server.Client()).AnyTimes()
	// Set expectation for GetHttpClient (used by CheckOrganizations)
	mockNA.EXPECT().GetHttpClient().Return(server.Client()).AnyTimes()
	// Mock GetConfiguration to return empty config (no token)
	mockNA.EXPECT().GetConfiguration().Return(configuration.New()).AnyTimes()

	logger := zerolog.Nop()
	config := configuration.New()
	checker := NewChecker(mockNA, &logger, config)

	// Run connectivity check
	result, err := checker.CheckConnectivity()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify result structure
	if result.StartTime.IsZero() {
		t.Error("Expected StartTime to be set")
	}
	if result.EndTime.IsZero() {
		t.Error("Expected EndTime to be set")
	}
	if result.EndTime.Before(result.StartTime) {
		t.Error("Expected EndTime to be after StartTime")
	}

	// Verify we got results for all hosts
	if len(result.HostResults) != 3 { // We're testing with 3 hosts
		t.Errorf("Expected 3 host results, got %d", len(result.HostResults))
	}
}

// timeoutError implements error interface for testing
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// Helper function to create test organization response
func createTestOrgResponse() *contract.OrganizationsResponse {
	return &contract.OrganizationsResponse{
		Organizations: []contract.Organization{
			{
				Id: "org-1",
				Attributes: contract.OrgAttributes{
					Name: "Test Org 1",
					Slug: "test-org-1",
				},
				Relationships: contract.OrgRelationships{
					Group: struct {
						Data struct {
							Id   string `json:"id"`
							Type string `json:"type"`
						} `json:"data"`
					}{
						Data: struct {
							Id   string `json:"id"`
							Type string `json:"type"`
						}{
							Id:   "group-1",
							Type: "group",
						},
					},
				},
			},
			{
				Id: "org-2",
				Attributes: contract.OrgAttributes{
					Name: "Test Org 2",
					Slug: "test-org-2",
				},
				Relationships: contract.OrgRelationships{
					Group: struct {
						Data struct {
							Id   string `json:"id"`
							Type string `json:"type"`
						} `json:"data"`
					}{
						Data: struct {
							Id   string `json:"id"`
							Type string `json:"type"`
						}{
							Id:   "group-1",
							Type: "group",
						},
					},
				},
			},
		},
		Included: []contract.IncludedItem{
			{
				Id:   "group-1",
				Type: "group",
				Attributes: struct {
					Name string `json:"name"`
				}{
					Name: "Test Group",
				},
			},
		},
	}
}

// Helper function to verify organizations
func verifyOrganizations(t *testing.T, orgs []Organization, expectedCount int, expectDefault bool) {
	t.Helper()
	if len(orgs) != expectedCount {
		t.Errorf("Expected %d organizations, got %d", expectedCount, len(orgs))
		return
	}

	if expectedCount > 0 {
		if orgs[0].ID != "org-1" {
			t.Errorf("Expected first org ID to be 'org-1', got '%s'", orgs[0].ID)
		}
		if orgs[0].Name != "Test Org 1" {
			t.Errorf("Expected first org name to be 'Test Org 1', got '%s'", orgs[0].Name)
		}
		if expectDefault && orgs[0].IsDefault != true {
			t.Errorf("Expected first org to be default, got %v", orgs[0].IsDefault)
		} else if !expectDefault && orgs[0].IsDefault != false {
			t.Errorf("Expected no org to be default when GetDefaultOrgId fails, got %v", orgs[0].IsDefault)
		}
	}
}

func TestCheckOrganizations(t *testing.T) {
	t.Run("with token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock dependencies
		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

		// Set expectations
		mockApiClient.EXPECT().GetOrganizations(100).Return(createTestOrgResponse(), nil)
		mockApiClient.EXPECT().GetDefaultOrgId().Return("org-1", nil)

		// Create checker with mock API client
		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		// Test fetching organizations
		orgs, err := checker.CheckOrganizations("https://api.snyk.io")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// Verify organizations
		verifyOrganizations(t, orgs, 2, true)
	})

	t.Run("with token and GetDefaultOrgId error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock dependencies
		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

		// Create mock response with single org
		mockResponse := &contract.OrganizationsResponse{
			Organizations: []contract.Organization{
				createTestOrgResponse().Organizations[0],
			},
			Included: createTestOrgResponse().Included,
		}

		// Set expectations - GetDefaultOrgId returns an error
		mockApiClient.EXPECT().GetOrganizations(100).Return(mockResponse, nil)
		mockApiClient.EXPECT().GetDefaultOrgId().Return("", errors.New("failed to get default org"))

		// Create checker with mock API client
		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		// Test fetching organizations
		orgs, err := checker.CheckOrganizations("https://api.snyk.io")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// Verify organizations
		verifyOrganizations(t, orgs, 1, false)
	})

	t.Run("without token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)

		// Create config without token and disable OAuth
		configNoToken := configuration.New()
		// Make sure OAuth is disabled by setting the disable flag
		configNoToken.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")

		checkerNoToken := NewCheckerWithApiClient(mockNA, &logger, configNoToken, mockApiClient)

		orgs, err := checkerNoToken.CheckOrganizations("https://api.snyk.io")
		if err != nil {
			t.Errorf("Expected no error when no token configured, got: %v", err)
		}
		if orgs != nil {
			t.Errorf("Expected nil organizations when no token configured, got %v", orgs)
		}
	})

	t.Run("with API error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

		// Set expectations for error case
		mockApiClient.EXPECT().GetOrganizations(100).Return(nil, errors.New("API error"))

		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		_, err := checker.CheckOrganizations("https://api.snyk.io")
		if err == nil {
			t.Error("Expected error from API call")
		}
		if err.Error() != "API error" {
			t.Errorf("Expected 'API error', got: %v", err)
		}
	})
}
