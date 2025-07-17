package connectivity

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func TestNewChecker(t *testing.T) {
	// Create mock NetworkAccess
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockNA := mocks.NewMockNetworkAccess(ctrl)
	logger := zerolog.Nop()
	config := configuration.New()

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
			name:    "No proxy set",
			envVars: map[string]string{},
			expected: ProxyConfig{
				Detected: false,
			},
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
				"HTTPS_PROXY": "http://https-proxy.example.com:8080",
				"https_proxy": "http://https-proxy-lower.example.com:8080",
				"HTTP_PROXY":  "http://http-proxy.example.com:8080",
				"http_proxy":  "http://http-proxy-lower.example.com:8080",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://https-proxy.example.com:8080",
				Variable: "HTTPS_PROXY",
			},
		},
		{
			name: "lowercase no_proxy used",
			envVars: map[string]string{
				"HTTP_PROXY": "http://proxy.example.com:8080",
				"no_proxy":   "*.local,10.0.0.0/8",
			},
			expected: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:8080",
				Variable: "HTTP_PROXY",
				NoProxy:  "*.local,10.0.0.0/8",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test environment variables using t.Setenv
			// First clear relevant proxy variables
			t.Setenv("HTTPS_PROXY", "")
			t.Setenv("https_proxy", "")
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("http_proxy", "")
			t.Setenv("NO_PROXY", "")
			t.Setenv("no_proxy", "")

			// Set test environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			// Create checker
			logger := zerolog.Nop()
			mockNA := mocks.NewMockNetworkAccess(gomock.NewController(t))
			config := configuration.New()
			checker := NewChecker(mockNA, &logger, config)

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
		name           string
		serverResponse int
		proxyAuth      string
		expectedStatus ConnectionStatus
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
			proxyAuth:      "Negotiate",
			expectedStatus: StatusProxyAuthSupported,
		},
		{
			name:           "Proxy auth required - Basic",
			serverResponse: http.StatusProxyAuthRequired,
			proxyAuth:      "Basic realm=\"Proxy\"",
			expectedStatus: StatusProxyAuthSupported,
		},
		{
			name:           "Proxy auth required - Unsupported",
			serverResponse: http.StatusProxyAuthRequired,
			proxyAuth:      "Digest realm=\"Proxy\"",
			expectedStatus: StatusProxyAuthUnsupported,
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
				if tt.proxyAuth != "" {
					w.Header().Set("Proxy-Authenticate", tt.proxyAuth)
				}
				w.WriteHeader(tt.serverResponse)
			}))
			defer server.Close()

			// Create checker with mock NetworkAccess
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockNA := mocks.NewMockNetworkAccess(ctrl)
			// Set expectation for GetUnauthorizedHttpClient (not GetHttpClient)
			mockNA.EXPECT().GetUnauthorizedHttpClient().Return(server.Client()).AnyTimes()

			logger := zerolog.Nop()
			config := configuration.New()
			checker := NewChecker(mockNA, &logger, config)

			// Test check host with server URL
			result := checker.checkHost(server.URL[8:]) // Remove https://

			// Verify status
			if result.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, result.Status)
			}
			if result.StatusCode != tt.serverResponse {
				t.Errorf("Expected status code %d, got %d", tt.serverResponse, result.StatusCode)
			}
			if tt.proxyAuth != "" && result.ProxyAuth != tt.proxyAuth {
				t.Errorf("Expected proxy auth '%s', got '%s'", tt.proxyAuth, result.ProxyAuth)
			}
		})
	}
}

func TestCheckHost_WithPath(t *testing.T) {
	// Test hosts with paths and ports
	tests := []struct {
		host        string
		expectedURL string
		displayHost string
	}{
		{
			host:        "api.snyk.io",
			expectedURL: "https://api.snyk.io",
			displayHost: "api.snyk.io",
		},
		{
			host:        "deeproxy.snyk.io/filters",
			expectedURL: "https://deeproxy.snyk.io/filters",
			displayHost: "deeproxy.snyk.io",
		},
		{
			host:        "downloads.snyk.io:443/cli/wasm/bundle.tar.gz",
			expectedURL: "https://downloads.snyk.io:443/cli/wasm/bundle.tar.gz",
			displayHost: "downloads.snyk.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Create checker with mock NetworkAccess
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockNA := mocks.NewMockNetworkAccess(ctrl)
			// Set expectation for GetUnauthorizedHttpClient
			mockNA.EXPECT().GetUnauthorizedHttpClient().Return(server.Client()).AnyTimes()

			logger := zerolog.Nop()
			config := configuration.New()
			checker := NewChecker(mockNA, &logger, config)

			// Mock the host to use our test server
			result := checker.checkHost(tt.host)

			// Verify display host extraction
			if result.DisplayHost != tt.displayHost {
				t.Errorf("Expected display host '%s', got '%s'", tt.displayHost, result.DisplayHost)
			}

			// Verify URL construction
			if result.URL != tt.expectedURL {
				t.Errorf("Expected URL '%s', got '%s'", tt.expectedURL, result.URL)
			}
		})
	}
}

func TestCategorizeError(t *testing.T) {
	logger := zerolog.Nop()
	mockNA := mocks.NewMockNetworkAccess(gomock.NewController(t))
	config := configuration.New()
	checker := NewChecker(mockNA, &logger, config)

	tests := []struct {
		name           string
		error          error
		expectedStatus ConnectionStatus
	}{
		{
			name:           "DNS error",
			error:          &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
			expectedStatus: StatusDNSError,
		},
		{
			name:           "Timeout error from os.IsTimeout",
			error:          &timeoutError{},
			expectedStatus: StatusTimeout,
		},
		{
			name:           "Timeout error in message",
			error:          errors.New("context deadline exceeded (Client.Timeout exceeded)"),
			expectedStatus: StatusTimeout,
		},
		{
			name:           "URL timeout error",
			error:          &url.Error{Op: "Get", URL: "https://example.com", Err: &timeoutError{}},
			expectedStatus: StatusTimeout,
		},
		{
			name:           "TLS error",
			error:          errors.New("tls: failed to verify certificate"),
			expectedStatus: StatusTLSError,
		},
		{
			name:           "SSL error",
			error:          errors.New("ssl handshake failure"),
			expectedStatus: StatusTLSError,
		},
		{
			name:           "Certificate error",
			error:          errors.New("x509: certificate signed by unknown authority"),
			expectedStatus: StatusTLSError,
		},
		{
			name:           "Generic connection error",
			error:          errors.New("connection refused"),
			expectedStatus: StatusBlocked,
		},
		{
			name:           "Network unreachable",
			error:          errors.New("network is unreachable"),
			expectedStatus: StatusBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := checker.categorizeError(tt.error)
			if status != tt.expectedStatus {
				t.Errorf("Expected status %v for error '%v', got %v", tt.expectedStatus, tt.error, status)
			}
		})
	}
}

func TestGenerateTODOs(t *testing.T) {
	logger := zerolog.Nop()
	mockNA := mocks.NewMockNetworkAccess(gomock.NewController(t))
	config := configuration.New()
	checker := NewChecker(mockNA, &logger, config)

	tests := []struct {
		name         string
		hostResult   HostResult
		expectedTODO struct {
			level    TodoLevel
			contains string
		}
	}{
		{
			name: "Reachable host",
			hostResult: HostResult{
				DisplayHost: "static.snyk.io",
				Status:      StatusReachable,
				StatusCode:  403,
			},
			expectedTODO: struct {
				level    TodoLevel
				contains string
			}{
				level:    TodoWarn,
				contains: "static.snyk.io",
			},
		},
		{
			name: "DNS error",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusDNSError,
			},
			expectedTODO: struct {
				level    TodoLevel
				contains string
			}{
				level:    TodoFail,
				contains: "DNS resolution failed",
			},
		},
		{
			name: "Proxy auth supported - Negotiate",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusProxyAuthSupported,
				ProxyAuth:   "Negotiate",
			},
			expectedTODO: struct {
				level    TodoLevel
				contains string
			}{
				level:    TodoInfo,
				contains: "Negotiate",
			},
		},
		{
			name: "Proxy auth supported - Basic",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusProxyAuthSupported,
				ProxyAuth:   "Basic",
			},
			expectedTODO: struct {
				level    TodoLevel
				contains string
			}{
				level:    TodoWarn,
				contains: "Basic",
			},
		},
		{
			name: "TLS error",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusTLSError,
			},
			expectedTODO: struct {
				level    TodoLevel
				contains string
			}{
				level:    TodoFail,
				contains: "TLS/SSL error",
			},
		},
		{
			name: "Blocked with error",
			hostResult: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusBlocked,
				Error:       errors.New("connection refused"),
			},
			expectedTODO: struct {
				level    TodoLevel
				contains string
			}{
				level:    TodoFail,
				contains: "connection refused",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ConnectivityCheckResult{}
			checker.generateTODOs(result, &tt.hostResult)

			if len(result.TODOs) == 0 {
				t.Fatal("Expected at least one TODO to be generated")
			}

			todo := result.TODOs[0]
			if todo.Level != tt.expectedTODO.level {
				t.Errorf("Expected TODO level %v, got %v", tt.expectedTODO.level, todo.Level)
			}

			if !strings.Contains(todo.Message, tt.expectedTODO.contains) {
				t.Errorf("Expected TODO message to contain '%s', got '%s'", tt.expectedTODO.contains, todo.Message)
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

// timeoutError implements net.Error interface for testing timeouts
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// mockError implements error interface for testing
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

func TestCheckOrganizations(t *testing.T) {
	// Create test server that returns organizations
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request for debugging
		t.Logf("Received request: %s %s", r.Method, r.URL.String())
		t.Logf("Authorization header: %s", r.Header.Get("Authorization"))

		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Logf("Authorization failed: expected 'Bearer test-token', got '%s'", auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Verify the API endpoint path
		if !strings.Contains(r.URL.Path, "/rest/orgs") {
			t.Logf("Path check failed: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Return mock organizations
		response := `{
			"data": [
				{
					"id": "org-1",
					"attributes": {
						"name": "Test Org 1",
						"slug": "test-org-1"
					},
					"relationships": {
						"group": {
							"data": {
								"id": "group-1"
							}
						}
					}
				},
				{
					"id": "org-2",
					"attributes": {
						"name": "Test Org 2",
						"slug": "test-org-2"
					},
					"relationships": {
						"group": {
							"data": {
								"id": "group-1"
							}
						}
					}
				}
			],
			"included": [
				{
					"id": "group-1",
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
	}))
	defer server.Close()

	// Test with token
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	logger := zerolog.Nop()
	mockNA := mocks.NewMockNetworkAccess(ctrl)
	config := configuration.New()
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	config.Set("api", server.URL)

	// Create a custom HTTP client that adds headers
	client := server.Client()
	originalTransport := client.Transport
	client.Transport = &headerAddingTransport{
		base:   originalTransport,
		config: config,
	}

	// Set expectations
	mockNA.EXPECT().GetHttpClient().Return(client).AnyTimes()
	mockNA.EXPECT().GetConfiguration().Return(config).AnyTimes()

	checker := NewChecker(mockNA, &logger, config)

	orgs, err := checker.CheckOrganizations(server.URL)
	t.Logf("CheckOrganizations returned: orgs=%v, err=%v", orgs, err)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify organizations
	if len(orgs) != 2 {
		t.Errorf("Expected 2 organizations, got %d", len(orgs))
	}
	if orgs[0].ID != "org-1" {
		t.Errorf("Expected first org ID to be 'org-1', got '%s'", orgs[0].ID)
	}
	if orgs[0].Name != "Test Org 1" {
		t.Errorf("Expected first org name to be 'Test Org 1', got '%s'", orgs[0].Name)
	}
	if orgs[0].Group.Name != "Test Group" {
		t.Errorf("Expected group name to be 'Test Group', got '%s'", orgs[0].Group.Name)
	}

	// Test without token
	configNoToken := configuration.New()
	// Clear any OAuth tokens by setting the oauth disable flag
	configNoToken.Set("snyk_oauth_token", "")
	configNoToken.Set("snyk_disable_analytics", "1")

	mockNANoToken := mocks.NewMockNetworkAccess(ctrl)
	mockNANoToken.EXPECT().GetConfiguration().Return(configNoToken).AnyTimes()

	checkerNoToken := NewChecker(mockNANoToken, &logger, configNoToken)

	orgsNoToken, err := checkerNoToken.CheckOrganizations(server.URL)
	// If OAuth is providing a token, we'll get a 401 error
	// If no token at all, we should get nil organizations
	if err != nil {
		// This is expected if OAuth is providing a token but it's not valid for our test server
		if !strings.Contains(err.Error(), "401") {
			t.Fatalf("Unexpected error: %v", err)
		}
	} else if orgsNoToken != nil {
		t.Errorf("Expected nil organizations when no token is set, got: %v", orgsNoToken)
	}

	// Test with HTTP error
	serverError := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer serverError.Close()

	configError := configuration.New()
	configError.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
	configError.Set("api", serverError.URL)

	mockNAError := mocks.NewMockNetworkAccess(ctrl)
	errorClient := serverError.Client()
	errorClient.Transport = &headerAddingTransport{
		base:   errorClient.Transport,
		config: configError,
	}
	mockNAError.EXPECT().GetHttpClient().Return(errorClient).AnyTimes()
	mockNAError.EXPECT().GetConfiguration().Return(configError).AnyTimes()

	checkerError := NewChecker(mockNAError, &logger, configError)

	_, err = checkerError.CheckOrganizations(serverError.URL)
	if err == nil {
		t.Error("Expected error for HTTP 500 response")
	}
}

// headerAddingTransport adds authorization headers to requests
type headerAddingTransport struct {
	base   http.RoundTripper
	config configuration.Configuration
}

func (t *headerAddingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add authorization header if token is present
	if t.config != nil {
		token := t.config.GetString(configuration.AUTHENTICATION_TOKEN)
		if token == "" {
			token = t.config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return t.base.RoundTrip(req)
}
