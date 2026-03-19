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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NotNil(t, checker, "Expected NewChecker to return a checker, got nil")
	assert.Equal(t, mockNA, checker.networkAccess, "Expected checker to have the provided NetworkAccess")
	assert.Equal(t, &logger, checker.logger, "Expected checker to have the provided logger")
	assert.Equal(t, config, checker.config, "Expected checker to have the provided configuration")
	assert.Equal(t, 10*time.Second, checker.timeout, "Expected default timeout to be 10s")
	assert.NotNil(t, checker.apiClient, "Expected checker to have an API client")
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
		{
			name: "Node and Kerberos env vars set",
			envVars: map[string]string{
				"NODE_EXTRA_CA_CERTS": "/tmp/custom-ca.pem",
				"KRB5_CONFIG":         "/etc/krb5.conf",
				"KRB5CCNAME":          "FILE:/tmp/krb5cc_1000",
			},
			expected: ProxyConfig{
				Detected:         false,
				NodeExtraCACerts: "/tmp/custom-ca.pem",
				KRB5Config:       "/etc/krb5.conf",
				KRB5CCName:       "FILE:/tmp/krb5cc_1000",
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
			assert.Equal(t, tt.expected.Detected, result.Detected, "Detected mismatch")
			assert.Equal(t, tt.expected.URL, result.URL, "URL mismatch")
			assert.Equal(t, tt.expected.Variable, result.Variable, "Variable mismatch")
			assert.Equal(t, tt.expected.NoProxy, result.NoProxy, "NoProxy mismatch")
			assert.Equal(t, tt.expected.NodeExtraCACerts, result.NodeExtraCACerts, "NodeExtraCACerts mismatch")
			assert.Equal(t, tt.expected.KRB5Config, result.KRB5Config, "KRB5Config mismatch")
			assert.Equal(t, tt.expected.KRB5CCName, result.KRB5CCName, "KRB5CCName mismatch")
		})
	}
}

func TestCheckHost(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse int
		serverHeader   map[string]string
		expectedStatus ConnectionStatus
		expectedAuth   string
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
			expectedStatus: StatusProxyAuthSupported,
			expectedAuth:   "Negotiate",
		},
		{
			name:           "Proxy auth required - Basic",
			serverResponse: http.StatusProxyAuthRequired,
			serverHeader: map[string]string{
				"Proxy-Authenticate": "Basic realm=\"Proxy\"",
			},
			expectedStatus: StatusProxyAuthSupported,
			expectedAuth:   "Basic realm=\"Proxy\"",
		},
		{
			name:           "Proxy auth required - Unsupported",
			serverResponse: http.StatusProxyAuthRequired,
			serverHeader: map[string]string{
				"Proxy-Authenticate": "Digest realm=\"Proxy\"",
			},
			expectedStatus: StatusProxyAuthUnsupported,
			expectedAuth:   "Digest realm=\"Proxy\"",
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
			require.NoError(t, err, "Failed to parse server URL")
			host := serverURL.Host

			// Test checkHost
			result := checker.checkHost(host)

			// Verify results
			assert.Equal(t, tt.expectedStatus, result.Status, "Status mismatch")
			assert.Equal(t, tt.expectedAuth, result.ProxyAuth, "Proxy auth mismatch")
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
			require.NoError(t, err, "Failed to parse server URL")

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
			assert.Equal(t, tt.expectedPath, requestPath, "Request path mismatch")
			assert.Equal(t, StatusOK, result.Status, "Expected status OK")
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
			assert.Equal(t, tt.expectedStatus, status, "Expected status for error %v", tt.err)
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
				assert.Empty(t, result.TODOs, "Expected no TODOs")
			} else {
				require.NotEmpty(t, result.TODOs, "Expected TODO to be generated")
				// Check if expected TODO message is present
				found := false
				for _, todo := range result.TODOs {
					if strings.Contains(todo.Message, tt.expectedTODO) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected TODO containing '%s', got %v", tt.expectedTODO, result.TODOs)
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
	require.NoError(t, err, "Unexpected error")
	require.NotNil(t, result)

	// Verify result structure
	assert.False(t, result.StartTime.IsZero(), "Expected StartTime to be set")
	assert.False(t, result.EndTime.IsZero(), "Expected EndTime to be set")
	assert.False(t, result.EndTime.Before(result.StartTime), "Expected EndTime to be after StartTime")

	// Verify we got results for all hosts
	assert.Len(t, result.HostResults, 3, "Expected 3 host results") // We're testing with 3 hosts
}

func TestCheckConnectivityWithMaxOrgCount(t *testing.T) {
	// Create a test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	// Override SnykHosts for testing
	cleanup := SetSnykHostsForTesting([]string{"api.snyk.io"})
	defer cleanup()

	t.Run("respects max-org-count from configuration", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock dependencies
		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)

		// Configure with authentication token and custom max-org-count
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set("max-org-count", 25)
		config.Set("insecure", true)

		// Create HTTP client for mock
		httpClient := server.Client()
		mockNA.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
		mockNA.EXPECT().GetUnauthorizedHttpClient().Return(httpClient).AnyTimes()

		// Expect GetOrganizations to be called with limit from config
		mockApiClient.EXPECT().GetOrganizations(25).Return(createTestOrgResponse(), nil)
		mockApiClient.EXPECT().GetDefaultOrgId().Return("org-1", nil)

		// Create checker
		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		// Run connectivity check
		result, err := checker.CheckConnectivity()
		require.NoError(t, err, "CheckConnectivity failed")
		require.NotNil(t, result)

		// Verify organizations were fetched
		assert.Len(t, result.Organizations, 2, "Expected 2 organizations")
	})

	t.Run("uses default when max-org-count is not set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock dependencies
		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)

		// Configure with authentication token but no max-org-count
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set("insecure", true)

		// Create HTTP client for mock
		httpClient := server.Client()
		mockNA.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
		mockNA.EXPECT().GetUnauthorizedHttpClient().Return(httpClient).AnyTimes()

		// Expect GetOrganizations to be called with default limit of 100
		mockApiClient.EXPECT().GetOrganizations(100).Return(createTestOrgResponse(), nil)
		mockApiClient.EXPECT().GetDefaultOrgId().Return("org-1", nil)

		// Create checker
		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		// Run connectivity check
		result, err := checker.CheckConnectivity()
		require.NoError(t, err, "CheckConnectivity failed")
		require.NotNil(t, result)

		// Verify organizations were fetched
		assert.Len(t, result.Organizations, 2, "Expected 2 organizations")
	})

	t.Run("uses default when max-org-count is invalid", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock dependencies
		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)

		// Configure with authentication token and invalid max-org-count
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")
		config.Set("max-org-count", -5)
		config.Set("insecure", true)

		// Create HTTP client for mock
		httpClient := server.Client()
		mockNA.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
		mockNA.EXPECT().GetUnauthorizedHttpClient().Return(httpClient).AnyTimes()

		// Expect GetOrganizations to be called with default limit of 100 (since -5 is invalid)
		mockApiClient.EXPECT().GetOrganizations(100).Return(createTestOrgResponse(), nil)
		mockApiClient.EXPECT().GetDefaultOrgId().Return("org-1", nil)

		// Create checker
		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		// Run connectivity check
		result, err := checker.CheckConnectivity()
		require.NoError(t, err, "CheckConnectivity failed")
		require.NotNil(t, result)

		// Verify organizations were fetched
		assert.Len(t, result.Organizations, 2, "Expected 2 organizations")
	})
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
					Name:    "Test Org 1",
					Slug:    "test-org-1",
					GroupId: "group-id-1",
				},
				Relationships: contract.OrgRelationships{},
			},
			{
				Id: "org-2",
				Attributes: contract.OrgAttributes{
					Name:    "Test Org 2",
					Slug:    "test-org-2",
					GroupId: "group-id-2",
				},
				Relationships: contract.OrgRelationships{},
			},
		},
	}
}

// Helper function to verify organizations
func verifyOrganizations(t *testing.T, orgs []Organization, expectedCount int, expectDefault bool) {
	t.Helper()
	assert.Len(t, orgs, expectedCount, "Did not get the expected number of organizations")
	if expectedCount == 0 {
		return
	}
	require.NotEmpty(t, orgs)

	assert.Equal(t, "org-1", orgs[0].ID, "Expected first org ID")
	assert.Equal(t, "group-id-1", orgs[0].GroupID, "Expected first org GroupID")
	assert.Equal(t, "Test Org 1", orgs[0].Name, "Expected first org name")
	assert.Equal(t, "test-org-1", orgs[0].Slug, "Expected first org slug")
	if expectDefault {
		assert.True(t, orgs[0].IsDefault, "Expected first org to be default")
	} else {
		assert.False(t, orgs[0].IsDefault, "Expected no org to be default when GetDefaultOrgId fails")
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
		orgs, err := checker.CheckOrganizations(100)
		require.NoError(t, err, "Expected no error")

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
		}

		// Set expectations - GetDefaultOrgId returns an error
		mockApiClient.EXPECT().GetOrganizations(100).Return(mockResponse, nil)
		mockApiClient.EXPECT().GetDefaultOrgId().Return("", errors.New("failed to get default org"))

		// Create checker with mock API client
		checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

		// Test fetching organizations
		orgs, err := checker.CheckOrganizations(100)
		require.NoError(t, err, "Expected no error")

		// Verify organizations
		verifyOrganizations(t, orgs, 1, false)
	})

	t.Run("without token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Clear all env vars that New() would pick up as auth tokens so the
		// "no token" branch is actually exercised regardless of the local environment.
		t.Setenv("SNYK_TOKEN", "")
		t.Setenv("SNYK_OAUTH_TOKEN", "")

		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)

		// Create config without token and disable OAuth
		configNoToken := configuration.New()
		// Make sure OAuth is disabled by setting the disable flag
		configNoToken.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")

		checkerNoToken := NewCheckerWithApiClient(mockNA, &logger, configNoToken, mockApiClient)

		orgs, err := checkerNoToken.CheckOrganizations(100)
		require.NoError(t, err, "Expected no error when no token configured")
		assert.Nil(t, orgs, "Expected nil organizations when no token configured")
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

		_, err := checker.CheckOrganizations(100)
		require.Error(t, err, "Expected error")
		assert.EqualError(t, err, "API error")
	})

	t.Run("with custom limit", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock dependencies
		logger := zerolog.Nop()
		mockNA := mocks.NewMockNetworkAccess(ctrl)
		mockApiClient := internalmocks.NewMockApiClient(ctrl)
		config := configuration.New()
		config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

		// Test with different limit values
		testCases := []struct {
			name  string
			limit int
		}{
			{"small limit", 10},
			{"medium limit", 50},
			{"large limit", 200},
			{"default limit", 100},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Set expectations with the specific limit
				mockApiClient.EXPECT().GetOrganizations(tc.limit).Return(createTestOrgResponse(), nil)
				mockApiClient.EXPECT().GetDefaultOrgId().Return("org-1", nil)

				// Create checker with mock API client
				checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

				// Test fetching organizations with the specific limit
				orgs, err := checker.CheckOrganizations(tc.limit)
				require.NoError(t, err, "Expected no error")

				// Verify organizations were returned
				assert.Len(t, orgs, 2, "Expected 2 organizations")
			})
		}
	})
}

func TestCheckConnectivityHandlesOrgError(t *testing.T) {
	// Create a test server for host connectivity checks
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Override SnykHosts for testing
	cleanup := SetSnykHostsForTesting([]string{"api.snyk.io"})
	defer cleanup()

	// Create controller for mocks
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Setup mocks
	mockNA := mocks.NewMockNetworkAccess(ctrl)
	mockApiClient := internalmocks.NewMockApiClient(ctrl)
	logger := zerolog.Nop()
	config := configuration.New()

	// Set authentication token to trigger organization fetch
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

	// Set expectation for GetUnauthorizedHttpClient (used by checkHost)
	mockNA.EXPECT().GetUnauthorizedHttpClient().Return(server.Client()).AnyTimes()

	// Mock GetOrganizations to return an error
	expectedError := errors.New("organization fetch error")
	mockApiClient.EXPECT().GetOrganizations(100).Return(nil, expectedError)

	// Create checker with mocked API client
	checker := NewCheckerWithApiClient(mockNA, &logger, config, mockApiClient)

	// Run connectivity check
	result, err := checker.CheckConnectivity()

	// The method should not return an error, but should populate OrgCheckError
	require.NoError(t, err, "Unexpected error from CheckConnectivity")
	require.NotNil(t, result)

	// Verify that OrgCheckError is set to the expected error
	assert.EqualError(t, result.OrgCheckError, expectedError.Error())

	// Verify other fields are still populated correctly
	assert.True(t, result.TokenPresent, "Expected TokenPresent to be true when token is configured")
	assert.Empty(t, result.Organizations, "Expected Organizations to be empty when fetch fails")
}
