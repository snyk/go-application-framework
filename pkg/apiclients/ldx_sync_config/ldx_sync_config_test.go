package ldx_sync_config_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ldx_sync_config "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
)

// Test configuration and helper types
type TestScenario struct {
	Name                   string
	RemoteUrl              string
	Org                    string
	ExpectedConfiguration  *ldx_sync_config.Configuration
	ExpectedConfigResponse *v20241015.ConfigResponse
	StatusCode             int
	ExpectError            bool
	ErrorContains          string
}

// Test server configuration
type TestServerConfig struct {
	HandlerFunc http.HandlerFunc
	StatusCode  int
	Response    interface{}
}

// Helper functions for creating pointers
func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func timePtr(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return &time.Time{}
	}
	return &t
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Common test data builders
func createBasicTestData() TestScenario {
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	expectedConfiguration := &ldx_sync_config.Configuration{
		Organization: org,
		SeverityFilter: &ldx_sync_config.SeverityFilter{
			Critical: true,
			High:     true,
			Medium:   true,
			Low:      false,
		},
		ProductConfig: &ldx_sync_config.ProductConfig{
			Code:      true,
			Container: false,
			Iac:       true,
			Oss:       true,
		},
		AutoScan:       true,
		TrustedFolders: []string{"/trusted/path1", "/trusted/path2"},
		ProxyConfig: &ldx_sync_config.ProxyConfig{
			Http:     "http://proxy.example.com:8080",
			Https:    "https://proxy.example.com:8080",
			Insecure: false,
			NoProxy:  "localhost,127.0.0.1",
		},
	}

	configID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	expectedConfigResponse := &v20241015.ConfigResponse{
		Data: v20241015.ConfigResource{
			Id:   configID,
			Type: v20241015.ConfigResourceTypeConfig,
			Attributes: v20241015.ConfigAttributes{
				ConfigData: v20241015.ConfigData{
					Organizations: &[]v20241015.Organization{
						{
							Id:        org,
							IsDefault: boolPtr(true),
						},
					},
					FilterConfig: &v20241015.FilterConfig{
						Severities: &struct {
							Critical *bool `json:"critical,omitempty"`
							High     *bool `json:"high,omitempty"`
							Low      *bool `json:"low,omitempty"`
							Medium   *bool `json:"medium,omitempty"`
						}{
							Critical: boolPtr(true),
							High:     boolPtr(true),
							Medium:   boolPtr(true),
							Low:      boolPtr(false),
						},
					},
					IdeConfig: &v20241015.IdeConfig{
						ProductConfig: &v20241015.ProductConfig{
							Code:      boolPtr(true),
							Container: boolPtr(false),
							Iac:       boolPtr(true),
							Oss:       boolPtr(true),
						},
						ScanConfig: &v20241015.ScanConfig{
							Automatic: boolPtr(true),
						},
						TrustConfig: &v20241015.TrustConfig{
							TrustedFolders: &[]string{"/trusted/path1", "/trusted/path2"},
						},
					},
					ProxyConfig: &v20241015.ProxyConfig{
						Http:     stringPtr("http://proxy.example.com:8080"),
						Https:    stringPtr("https://proxy.example.com:8080"),
						Insecure: boolPtr(false),
						NoProxy:  stringPtr("localhost,127.0.0.1"),
					},
				},
			},
		},
	}

	return TestScenario{
		Name:                   "Basic Configuration",
		RemoteUrl:              remoteUrl,
		Org:                    org,
		ExpectedConfiguration:  expectedConfiguration,
		ExpectedConfigResponse: expectedConfigResponse,
		StatusCode:             http.StatusOK,
		ExpectError:            false,
	}
}

func createMinimalTestData() TestScenario {
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	configID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	minimalResponse := &v20241015.ConfigResponse{
		Data: v20241015.ConfigResource{
			Id:   configID,
			Type: v20241015.ConfigResourceTypeConfig,
			Attributes: v20241015.ConfigAttributes{
				ConfigData: v20241015.ConfigData{
					Organizations: &[]v20241015.Organization{
						{
							Id:        org,
							IsDefault: boolPtr(true),
						},
					},
				},
			},
		},
	}

	expectedConfiguration := &ldx_sync_config.Configuration{
		Organization: org,
	}

	return TestScenario{
		Name:                   "Minimal Configuration",
		RemoteUrl:              remoteUrl,
		Org:                    org,
		ExpectedConfiguration:  expectedConfiguration,
		ExpectedConfigResponse: minimalResponse,
		StatusCode:             http.StatusOK,
		ExpectError:            false,
	}
}

func createErrorTestData() TestScenario {
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	return TestScenario{
		Name:                   "API Error",
		RemoteUrl:              remoteUrl,
		Org:                    org,
		ExpectedConfigResponse: nil, // Error responses don't use ConfigResponse
		StatusCode:             http.StatusNotFound,
		ExpectError:            true,
		ErrorContains:          "unexpected response",
	}
}

// Generic test server creator
func createTestServer(t *testing.T, config TestServerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.HandlerFunc != nil {
			config.HandlerFunc(w, r)
			return
		}

		// Default handler
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(config.StatusCode)

		if config.Response != nil {
			responseBytes, err := json.Marshal(config.Response)
			if err != nil {
				http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
				return
			}
			_, err = w.Write(responseBytes)
			if err != nil {
				t.Logf("Failed to write response: %v", err)
			}
		}
	}))
}

// Generic client creator
func createTestClient(t *testing.T, serverURL string, options ...ldx_sync_config.ConfigOption) ldx_sync_config.LdxSyncConfigClient {
	t.Helper()
	client, err := ldx_sync_config.NewLdxSyncConfigClient(serverURL, options...)
	require.NoError(t, err)
	return client
}

// Generic test runner
func runConfigurationTest(t *testing.T, scenario TestScenario) {
	t.Helper()
	t.Parallel()

	ctx := context.Background()

	// Create test server
	server := createTestServer(t, TestServerConfig{
		StatusCode: scenario.StatusCode,
		Response:   scenario.ExpectedConfigResponse,
	})
	defer server.Close()

	// Create client
	client := createTestClient(t, server.URL, ldx_sync_config.WithCustomHTTPClient(server.Client()))

	// Prepare parameters
	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: scenario.RemoteUrl,
		Org:       &scenario.Org,
	}

	// Execute test
	config, err := client.GetConfiguration(ctx, params)

	// Assertions
	if scenario.ExpectError {
		assert.Error(t, err)
		assert.Nil(t, config)
		if scenario.ErrorContains != "" {
			assert.Contains(t, err.Error(), scenario.ErrorContains)
		}
	} else {
		assert.NoError(t, err)
		require.NotNil(t, config)
		assert.Equal(t, scenario.ExpectedConfiguration.Organization, config.Organization)
		assert.Equal(t, scenario.ExpectedConfiguration.SeverityFilter, config.SeverityFilter)
		assert.Equal(t, scenario.ExpectedConfiguration.ProductConfig, config.ProductConfig)
		assert.Equal(t, scenario.ExpectedConfiguration.AutoScan, config.AutoScan)
		assert.Equal(t, scenario.ExpectedConfiguration.TrustedFolders, config.TrustedFolders)
		assert.Equal(t, scenario.ExpectedConfiguration.ProxyConfig, config.ProxyConfig)
	}
}

// Individual test functions
func Test_CreateClient_Defaults(t *testing.T) {
	t.Parallel()
	serverURL := "https://test.snyk.io/"
	client, err := ldx_sync_config.NewLdxSyncConfigClient(serverURL)
	assert.NotEmpty(t, client)
	assert.Nil(t, err)
}

func Test_GetConfiguration_Success(t *testing.T) {
	scenario := createBasicTestData()
	runConfigurationTest(t, scenario)
}

func Test_GetConfiguration_MinimalData(t *testing.T) {
	scenario := createMinimalTestData()
	runConfigurationTest(t, scenario)
}

func Test_GetConfiguration_APIError(t *testing.T) {
	scenario := createErrorTestData()
	runConfigurationTest(t, scenario)
}

func Test_GetConfiguration_NetworkError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	// Use non-listening port
	client, err := ldx_sync_config.NewLdxSyncConfigClient("http://127.0.0.1:1")
	require.NoError(t, err)

	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	config, err := client.GetConfiguration(ctx, params)

	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "failed to retrieve LDX-Sync configuration")
}

func Test_GetConfiguration_EmptyResponse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	configID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	emptyResponse := &v20241015.ConfigResponse{
		Data: v20241015.ConfigResource{
			Id:   configID,
			Type: v20241015.ConfigResourceTypeConfig,
			Attributes: v20241015.ConfigAttributes{
				ConfigData: v20241015.ConfigData{},
			},
		},
	}

	server := createTestServer(t, TestServerConfig{
		StatusCode: http.StatusOK,
		Response:   emptyResponse,
	})
	defer server.Close()

	client := createTestClient(t, server.URL, ldx_sync_config.WithCustomHTTPClient(server.Client()))

	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	config, err := client.GetConfiguration(ctx, params)

	assert.NoError(t, err)
	require.NotNil(t, config)
	assert.Empty(t, config.Organization)
	assert.Nil(t, config.SeverityFilter)
	assert.Nil(t, config.ProductConfig)
	assert.False(t, config.AutoScan)
	assert.Empty(t, config.TrustedFolders)
	assert.Nil(t, config.ProxyConfig)
}

func Test_NewLdxSyncConfigClient_CustomLogger(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	var logBuffer bytes.Buffer
	customLogger := zerolog.New(&logBuffer).With().Timestamp().Logger()

	server := createTestServer(t, TestServerConfig{
		HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		},
	})
	defer server.Close()

	client := createTestClient(t, server.URL,
		ldx_sync_config.WithLogger(&customLogger),
		ldx_sync_config.WithCustomHTTPClient(server.Client()),
	)

	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	_, err := client.GetConfiguration(ctx, params)
	if err != nil {
		t.Logf("Expected error: %v", err)
	}

	logOutput := logBuffer.String()
	t.Logf("Log output: %s", logOutput)
	assert.Contains(t, logOutput, "Retrieving LDX-Sync configuration")
	assert.Contains(t, logOutput, "unexpected response")
}

func Test_NewLdxSyncConfigClient_CustomAPIVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"
	customVersion := "2024-01-01"

	server := createTestServer(t, TestServerConfig{
		HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, customVersion, r.URL.Query().Get("version"))
			w.Header().Set("Content-Type", "application/vnd.api+json")
			w.WriteHeader(http.StatusOK)
			configID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
			responseBytes, err := json.Marshal(&v20241015.ConfigResponse{
				Data: v20241015.ConfigResource{
					Id:   configID,
					Type: v20241015.ConfigResourceTypeConfig,
					Attributes: v20241015.ConfigAttributes{
						ConfigData: v20241015.ConfigData{},
					},
				},
			})
			if err != nil {
				http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
				return
			}
			_, err = w.Write(responseBytes)
			if err != nil {
				t.Logf("Failed to write response: %v", err)
			}
		},
	})
	defer server.Close()

	client := createTestClient(t, server.URL,
		ldx_sync_config.WithAPIVersion(customVersion),
		ldx_sync_config.WithCustomHTTPClient(server.Client()),
	)

	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	config, err := client.GetConfiguration(ctx, params)

	assert.NoError(t, err)
	assert.NotNil(t, config)
}

func Test_GetConfiguration_MultipleOrganizations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"
	defaultOrg := "default-org-456"

	configID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	response := &v20241015.ConfigResponse{
		Data: v20241015.ConfigResource{
			Id:   configID,
			Type: v20241015.ConfigResourceTypeConfig,
			Attributes: v20241015.ConfigAttributes{
				ConfigData: v20241015.ConfigData{
					Organizations: &[]v20241015.Organization{
						{
							Id:        org,
							IsDefault: boolPtr(false),
						},
						{
							Id:        defaultOrg,
							IsDefault: boolPtr(true),
						},
					},
				},
			},
		},
	}

	server := createTestServer(t, TestServerConfig{
		StatusCode: http.StatusOK,
		Response:   response,
	})
	defer server.Close()

	client := createTestClient(t, server.URL, ldx_sync_config.WithCustomHTTPClient(server.Client()))

	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	config, err := client.GetConfiguration(ctx, params)

	assert.NoError(t, err)
	require.NotNil(t, config)
	// Should select the default organization
	assert.Equal(t, defaultOrg, config.Organization)
}

func Test_GetConfiguration_NoDefaultOrganization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	configID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	response := &v20241015.ConfigResponse{
		Data: v20241015.ConfigResource{
			Id:   configID,
			Type: v20241015.ConfigResourceTypeConfig,
			Attributes: v20241015.ConfigAttributes{
				ConfigData: v20241015.ConfigData{
					Organizations: &[]v20241015.Organization{
						{
							Id:        org,
							IsDefault: boolPtr(false),
						},
					},
				},
			},
		},
	}

	server := createTestServer(t, TestServerConfig{
		StatusCode: http.StatusOK,
		Response:   response,
	})
	defer server.Close()

	client := createTestClient(t, server.URL, ldx_sync_config.WithCustomHTTPClient(server.Client()))

	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	config, err := client.GetConfiguration(ctx, params)

	assert.NoError(t, err)
	require.NotNil(t, config)
	// Should select the first organization when no default is set
	assert.Equal(t, org, config.Organization)
}

// Test with complete data - keeping the comprehensive test as is due to its complexity
func Test_GetConfiguration_CompleteData(t *testing.T) {
	// Test with complete data including all new fields
	remoteUrl := "https://github.com/test/repo"
	org := "test-org-123"

	// Create a comprehensive test response
	configResponse := &v20241015.ConfigResponse{
		Data: v20241015.ConfigResource{
			Id:   uuid.MustParse("ea65b4b8-66bf-4f81-8f26-c172d16882f3"),
			Type: "config",
			Attributes: v20241015.ConfigAttributes{
				AttributeSource: v20241015.AttributeSource{
					RemoteUrl: &[]string{"config_data.folder_configs[].organizations"},
				},
				ConfigData: v20241015.ConfigData{
					AuthenticationMethod: func() *v20241015.ConfigDataAuthenticationMethod {
						method := v20241015.ConfigDataAuthenticationMethod("oauth")
						return &method
					}(),
					Endpoints: &v20241015.Endpoints{
						ApiEndpoint:  stringPtr("https://api.snyk.io"),
						CodeEndpoint: stringPtr("https://deeproxy.snyk.io"),
					},
					FilterConfig: &v20241015.FilterConfig{
						Cve:                &[]string{"CVE-2021-44228"},
						Cwe:                &[]string{"CWE-79"},
						RiskScoreThreshold: intPtr(400),
						Rule:               &[]string{"rule-123"},
						Severities: &struct {
							Critical *bool `json:"critical,omitempty"`
							High     *bool `json:"high,omitempty"`
							Low      *bool `json:"low,omitempty"`
							Medium   *bool `json:"medium,omitempty"`
						}{
							Critical: boolPtr(true),
							High:     boolPtr(true),
							Medium:   boolPtr(true),
							Low:      boolPtr(false),
						},
					},
					FolderConfigs: &[]v20241015.FolderConfig{
						{
							FolderPath: ".",
							Organizations: &[]v20241015.Organization{
								{
									Id:                   "498cf1c3-2ff2-40ad-86a9-e6f57f187fea",
									IsDefault:            boolPtr(true),
									Name:                 "test-org",
									PreferredByAlgorithm: boolPtr(false),
									ProjectCount:         intPtr(5),
									Slug:                 "test-org-slug",
								},
							},
							RemoteUrl:              "https://github.com/snyk/snyk-ls",
							AdditionalEnvironment:  &[]string{"ENV_VAR=value"},
							AdditionalParameters:   &[]string{"--param=value"},
							PreScanExecuteCommand:  stringPtr("npm install"),
							PostScanExecuteCommand: stringPtr("npm run cleanup"),
							ReferenceBranch:        stringPtr("main"),
							ReferenceFolder:        stringPtr("src"),
						},
					},
					IdeConfig: &v20241015.IdeConfig{
						BinaryManagementConfig: &v20241015.BinaryManagementConfig{
							AutomaticDownload: boolPtr(true),
							CliPath:           stringPtr("/usr/local/bin/snyk"),
						},
						CodeActions: &struct {
							OpenBrowser     *v20241015.CodeActions `json:"open_browser,omitempty"`
							OpenLearnLesson *v20241015.CodeActions `json:"open_learn_lesson,omitempty"`
							ScaUpgrade      *v20241015.CodeActions `json:"sca_upgrade,omitempty"`
						}{
							OpenBrowser: &[]v20241015.CodeAction{
								{
									Enabled:         boolPtr(false),
									IntegrationName: stringPtr("VS_CODE"),
								},
							},
							OpenLearnLesson: &[]v20241015.CodeAction{
								{
									Enabled:         boolPtr(true),
									IntegrationName: stringPtr("VS_CODE"),
								},
							},
							ScaUpgrade: &[]v20241015.CodeAction{
								{
									Enabled:         boolPtr(true),
									IntegrationName: stringPtr("VS_CODE"),
								},
							},
						},
						HoverVerbosity: intPtr(2),
						IssueViewConfig: &v20241015.IssueViewConfig{
							IgnoredIssues: boolPtr(false),
							OpenIssues:    boolPtr(true),
						},
						ProductConfig: &v20241015.ProductConfig{
							Code:      boolPtr(true),
							Container: boolPtr(true),
							Iac:       boolPtr(true),
							Oss:       boolPtr(true),
						},
						ScanConfig: &v20241015.ScanConfig{
							Automatic: boolPtr(true),
							NetNew:    boolPtr(true),
						},
						TrustConfig: &v20241015.TrustConfig{
							Enable:         boolPtr(true),
							TrustedFolders: &[]string{"/trusted/path1", "/trusted/path2"},
						},
					},
					Organizations: &[]v20241015.Organization{
						{
							Id:                   "498cf1c3-2ff2-40ad-86a9-e6f57f187fea",
							IsDefault:            boolPtr(true),
							Name:                 "test-org",
							PreferredByAlgorithm: boolPtr(false),
							ProjectCount:         intPtr(5),
							Slug:                 "test-org-slug",
						},
					},
					ProxyConfig: &v20241015.ProxyConfig{
						Http:     stringPtr("http://proxy.example.com:8080"),
						Https:    stringPtr("https://proxy.example.com:8443"),
						Insecure: boolPtr(false),
						NoProxy:  stringPtr("localhost,127.0.0.1"),
					},
				},
				CreatedAt:      timePtr("2025-09-15T13:28:12.244607736Z"),
				LastModifiedAt: parseTime("2025-09-15T13:28:12.244607736Z"),
				Scope:          "global",
				Policy: &v20241015.Policy{
					EnforcedAttributes: &[]string{"filter_config.severities.critical"},
					LockedAttributes:   &[]string{"proxy_config.http"},
				},
			},
		},
		Jsonapi: &struct {
			Version *v20241015.ConfigResponseJsonapiVersion `json:"version,omitempty"`
		}{
			Version: func() *v20241015.ConfigResponseJsonapiVersion {
				v := v20241015.ConfigResponseJsonapiVersion("1.0")
				return &v
			}(),
		},
		Links: &struct {
			Self *string `json:"self,omitempty"`
		}{
			Self: stringPtr("https://api.snyk.io/rest/ldx_sync/config"),
		},
		Meta: &v20241015.ResponseMeta{
			RequestTime: timePtr("2025-09-15T13:28:12.244607736Z"),
		},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ldx_sync/config", r.URL.Path)
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))
		assert.Equal(t, remoteUrl, r.URL.Query().Get("remote_url"))
		assert.Equal(t, org, r.URL.Query().Get("org"))

		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(configResponse)
		if err != nil {
			t.Logf("Failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create client
	client, err := ldx_sync_config.NewLdxSyncConfigClient(server.URL)
	require.NoError(t, err)

	// Test GetConfiguration
	params := ldx_sync_config.GetConfigurationParams{
		RemoteUrl: remoteUrl,
		Org:       &org,
	}

	config, err := client.GetConfiguration(context.Background(), params)
	assert.NoError(t, err)
	require.NotNil(t, config)

	// Test all new fields
	assert.Equal(t, "oauth", *config.AuthenticationMethod)
	assert.Equal(t, "https://api.snyk.io", *config.Endpoints.ApiEndpoint)
	assert.Equal(t, "https://deeproxy.snyk.io", *config.Endpoints.CodeEndpoint)

	// Test complete filter config
	require.NotNil(t, config.FilterConfig)
	assert.Equal(t, []string{"CVE-2021-44228"}, config.FilterConfig.Cve)
	assert.Equal(t, []string{"CWE-79"}, config.FilterConfig.Cwe)
	assert.Equal(t, 400, *config.FilterConfig.RiskScoreThreshold)
	assert.Equal(t, []string{"rule-123"}, config.FilterConfig.Rule)
	require.NotNil(t, config.FilterConfig.Severities)
	assert.True(t, config.FilterConfig.Severities.Critical)
	assert.True(t, config.FilterConfig.Severities.High)
	assert.True(t, config.FilterConfig.Severities.Medium)
	assert.False(t, config.FilterConfig.Severities.Low)

	// Test folder configs
	require.Len(t, config.FolderConfigs, 1)
	folderConfig := config.FolderConfigs[0]
	assert.Equal(t, ".", folderConfig.FolderPath)
	assert.Equal(t, "https://github.com/snyk/snyk-ls", folderConfig.RemoteUrl)
	assert.Equal(t, []string{"ENV_VAR=value"}, folderConfig.AdditionalEnvironment)
	assert.Equal(t, []string{"--param=value"}, folderConfig.AdditionalParameters)
	assert.Equal(t, "npm install", *folderConfig.PreScanExecuteCommand)
	assert.Equal(t, "npm run cleanup", *folderConfig.PostScanExecuteCommand)
	assert.Equal(t, "main", *folderConfig.ReferenceBranch)
	assert.Equal(t, "src", *folderConfig.ReferenceFolder)
	require.Len(t, folderConfig.Organizations, 1)
	assert.Equal(t, "498cf1c3-2ff2-40ad-86a9-e6f57f187fea", folderConfig.Organizations[0].Id)

	// Test complete IDE config
	require.NotNil(t, config.IdeConfig)
	assert.True(t, *config.IdeConfig.BinaryManagementConfig.AutomaticDownload)
	assert.Equal(t, "/usr/local/bin/snyk", *config.IdeConfig.BinaryManagementConfig.CliPath)
	assert.Equal(t, 2, *config.IdeConfig.HoverVerbosity)
	assert.False(t, *config.IdeConfig.IssueViewConfig.IgnoredIssues)
	assert.True(t, *config.IdeConfig.IssueViewConfig.OpenIssues)
	assert.True(t, *config.IdeConfig.ScanConfig.Automatic)
	assert.True(t, *config.IdeConfig.ScanConfig.NetNew)
	assert.True(t, *config.IdeConfig.TrustConfig.Enable)
	assert.Equal(t, []string{"/trusted/path1", "/trusted/path2"}, config.IdeConfig.TrustConfig.TrustedFolders)

	// Test code actions
	require.NotNil(t, config.IdeConfig.CodeActions)
	assert.Len(t, config.IdeConfig.CodeActions.OpenBrowser, 1)
	assert.Len(t, config.IdeConfig.CodeActions.OpenLearnLesson, 1)
	assert.Len(t, config.IdeConfig.CodeActions.ScaUpgrade, 1)
	assert.False(t, *config.IdeConfig.CodeActions.OpenBrowser[0].Enabled)
	assert.True(t, *config.IdeConfig.CodeActions.OpenLearnLesson[0].Enabled)
	assert.True(t, *config.IdeConfig.CodeActions.ScaUpgrade[0].Enabled)

	// Test complete organizations
	require.Len(t, config.Organizations, 1)
	orgData := config.Organizations[0]
	assert.Equal(t, "498cf1c3-2ff2-40ad-86a9-e6f57f187fea", orgData.Id)
	assert.True(t, *orgData.IsDefault)
	assert.Equal(t, "test-org", orgData.Name)
	assert.False(t, *orgData.PreferredByAlgorithm)
	assert.Equal(t, 5, *orgData.ProjectCount)
	assert.Equal(t, "test-org-slug", orgData.Slug)

	// Test metadata
	require.NotNil(t, config.AttributeSource)
	assert.Equal(t, []string{"config_data.folder_configs[].organizations"}, config.AttributeSource.RemoteUrl)
	assert.NotNil(t, config.CreatedAt)
	assert.NotNil(t, config.LastModifiedAt)
	assert.Equal(t, "global", *config.Scope)
	require.NotNil(t, config.Policy)
	assert.Equal(t, []string{"filter_config.severities.critical"}, config.Policy.EnforcedAttributes)
	assert.Equal(t, []string{"proxy_config.http"}, config.Policy.LockedAttributes)
}
