package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/error-catalog-golang-public/code"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Code_entrypoint(t *testing.T) {
	org := "1234"
	sastSettingsCalled := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.URL)
		if strings.HasSuffix(r.URL.String(), "/v1/cli-config/settings/sast?org="+org) {
			sastSettingsCalled++
			sastSettings := &sast_contract.SastResponse{
				SastEnabled: true,
				LocalCodeEngine: sast_contract.LocalCodeEngine{
					Enabled: true, /* ensures that legacycli will be called */
				},
			}

			err := json.NewEncoder(w).Encode(sastSettings)
			assert.NoError(t, err)
		} else if strings.Contains(r.URL.String(), "/v1/cli-config/feature-flags/") {
			featureFlag := contract.OrgFeatureFlagResponse{
				Ok: true,
			}

			err := json.NewEncoder(w).Encode(featureFlag)
			assert.NoError(t, err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	expectedData := "Hello World"
	flagString := "--user-=bla"
	callback1 := func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		typeId := workflow.NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
		d := workflow.NewData(typeId, "text/plain", expectedData)
		assert.Equal(t, []string{flagString}, invocation.GetConfiguration().Get(configuration.RAW_CMD_ARGS))
		return []workflow.Data{d}, nil
	}

	// set
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.ORGANIZATION, org)
	config.AddDefaultValue(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP, configuration.StandardDefaultValueFunction(constants.SNYK_DEFAULT_ALLOWED_HOST_REGEXP))

	engine := workflow.NewWorkFlowEngine(config)

	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	// Create legacycli workflow
	mockLegacyCliWorkflowId := workflow.NewWorkflowIdentifier("legacycli")
	entry1, err := engine.Register(mockLegacyCliWorkflowId, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("1", pflag.ExitOnError)), callback1)
	assert.Nil(t, err)
	assert.NotNil(t, entry1)

	err = engine.Init()
	assert.NoError(t, err)

	// Method under test
	wrkflw, ok := engine.GetWorkflow(WORKFLOWID_CODE)
	assert.True(t, ok)
	assert.NotNil(t, wrkflw)

	os.Args = []string{"cmd", flagString}

	rs, err := engine.InvokeWithConfig(WORKFLOWID_CODE, config)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, expectedData, rs[0].GetPayload().(string)) //nolint:errcheck //in this test, the type is clear
	assert.Equal(t, 2, sastSettingsCalled)
}

func Test_Code_legacyImplementation_happyPath(t *testing.T) {
	expectedData := "Hello World"
	flagString := "--user-=bla"
	callback1 := func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		typeId := workflow.NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
		d := workflow.NewData(typeId, "text/plain", expectedData)
		assert.Equal(t, []string{flagString}, invocation.GetConfiguration().Get(configuration.RAW_CMD_ARGS))
		return []workflow.Data{d}, nil
	}

	// set
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, false)
	config.Set(code_workflow.ConfigurationSastEnabled, true)

	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	// Create legacycli workflow
	mockLegacyCliWorkflowId := workflow.NewWorkflowIdentifier("legacycli")
	entry1, err := engine.Register(mockLegacyCliWorkflowId, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("1", pflag.ExitOnError)), callback1)
	assert.Nil(t, err)
	assert.NotNil(t, entry1)

	err = engine.Init()
	assert.NoError(t, err)

	// Method under test
	wrkflw, ok := engine.GetWorkflow(WORKFLOWID_CODE)
	assert.True(t, ok)
	assert.NotNil(t, wrkflw)

	os.Args = []string{"cmd", flagString}

	rs, err := engine.InvokeWithConfig(WORKFLOWID_CODE, config)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, expectedData, rs[0].GetPayload().(string)) //nolint:errcheck //in this test, the type is clear
}

func Test_Code_nativeImplementation_happyPath(t *testing.T) {
	numberOfArtifacts := rand.Int()
	expectedSummary := json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 3, Open: 2, Ignored: 1},
			{Severity: "medium", Total: 1, Open: 1},
			{Severity: "low", Total: 1, Open: 0, Ignored: 1},
		},
		Artifacts: numberOfArtifacts,
	}

	expectedRepoUrl := "https://hello.world"
	expectedPath := "/var/lib/something"

	config := configuration.NewInMemory()
	config.Set(configuration.FLAG_REMOTE_REPO_URL, expectedRepoUrl)
	config.Set(configuration.INPUT_DIRECTORY, expectedPath)

	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	analysisFunc := func(path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
		assert.Equal(t, expectedPath, path)
		suppressions := []sarif.Suppression{
			{
				Status: sarif.Accepted,
			},
		}
		response := &sarif.SarifResponse{
			Sarif: sarif.SarifDocument{
				Runs: []sarif.Run{
					{
						Results: []sarif.Result{
							{Level: "error"},
							{Level: "warning"},
						},
						Properties: sarif.RunProperties{
							Coverage: []struct {
								Files       int    `json:"files"`
								IsSupported bool   `json:"isSupported"`
								Lang        string `json:"lang"`
								Type        string `json:"type"`
							}{{
								Files:       numberOfArtifacts,
								IsSupported: true,
								Lang:        "",
								Type:        "",
							}},
						},
					},
					{
						Results: []sarif.Result{
							{Level: "error"},
							{Level: "error", Suppressions: suppressions},
						},
					},
					{
						Results: []sarif.Result{
							{Level: "note", Suppressions: suppressions},
						},
					},
				},
			},
		}
		return response, &scan.ResultMetaData{}, nil
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, 2, len(rs))

	for _, v := range rs {
		if v.GetContentType() == content_type.TEST_SUMMARY {
			actualSummary := &json_schemas.TestSummary{}
			err = json.Unmarshal(v.GetPayload().([]byte), actualSummary) //nolint:errcheck //in this test, the type is clear
			assert.NoError(t, err)

			count := 0
			for _, expectedResult := range expectedSummary.Results {
				for _, actualResult := range actualSummary.Results {
					if expectedResult.Severity == actualResult.Severity {
						assert.Equal(t, expectedResult, actualResult)
						count++
					}
				}
			}
			assert.Equal(t, len(expectedSummary.Results), count)
			assert.Equal(t, expectedSummary.Artifacts, actualSummary.Artifacts)
		} else if v.GetContentType() == content_type.LOCAL_FINDING_MODEL {
			_, ok := v.GetPayload().([]byte)
			assert.True(t, ok)
		} else {
			assert.Fail(t, "unexpected data")
		}
	}
}

func Test_Code_nativeImplementation_analysisFails(t *testing.T) {
	config := configuration.NewInMemory()
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	analysisFunc := func(string, func() *http.Client, *zerolog.Logger, configuration.Configuration, ui.UserInterface) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
		return nil, nil, fmt.Errorf("something went wrong")
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.Error(t, err)
	assert.Nil(t, rs)
}

func Test_Code_nativeImplementation_analysisNil(t *testing.T) {
	config := configuration.NewInMemory()
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	analysisFunc := func(path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
		return nil, nil, nil
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(rs))

	summary := findTestSummary(rs)
	dataErrors := summary.GetErrorList()
	assert.Equal(t, 1, len(dataErrors))
	assert.Equal(t, dataErrors[0].ErrorCode, code.NewUnsupportedProjectError("").ErrorCode)
}

func findTestSummary(rs []workflow.Data) workflow.Data {
	var summary workflow.Data
	for _, v := range rs {
		if v.GetContentType() == content_type.TEST_SUMMARY {
			summary = v
		}
	}
	return summary
}

func Test_Code_nativeImplementation_analysisEmpty(t *testing.T) {
	config := configuration.NewInMemory()
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	analysisFunc := func(path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
		response := &sarif.SarifResponse{
			Sarif: sarif.SarifDocument{
				Runs: []sarif.Run{
					{
						Properties: sarif.RunProperties{
							Coverage: []struct {
								Files       int    `json:"files"`
								IsSupported bool   `json:"isSupported"`
								Lang        string `json:"lang"`
								Type        string `json:"type"`
							}{{
								Files:       0,
								IsSupported: false,
								Lang:        "",
								Type:        "",
							}},
						},
					},
				},
			},
		}
		return response, &scan.ResultMetaData{}, nil
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.NoError(t, err)
	assert.Equal(t, len(rs), 2)

	summary := findTestSummary(rs)
	dataErrors := summary.GetErrorList()
	assert.Equal(t, 1, len(dataErrors))
	assert.Equal(t, dataErrors[0].ErrorCode, code.NewUnsupportedProjectError("").ErrorCode)
}

func Test_Code_FF_CODE_CONSISTENT_IGNORES(t *testing.T) {
	response := contract.OrgFeatureFlagResponse{}
	responseNativeImpl := contract.OrgFeatureFlagResponse{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := json.Marshal(response)

		if strings.Contains(r.URL.Path, code_workflow.FfNameNativeImplementation) {
			data, err = json.Marshal(responseNativeImpl)
		}

		assert.NoError(t, err)
		fmt.Fprintln(w, string(data))
	}))
	defer ts.Close()

	orgId := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, ts.URL)

	engine := workflow.NewWorkFlowEngine(config)
	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	t.Run("Feature Flag set", func(t *testing.T) {
		config.Set(configuration.ORGANIZATION, orgId)
		response = contract.OrgFeatureFlagResponse{Code: http.StatusOK, Ok: true}
		consistentIgnores := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
		assert.True(t, consistentIgnores)
	})

	t.Run("Feature Flag NOT set", func(t *testing.T) {
		config.Set(configuration.ORGANIZATION, orgId)
		response = contract.OrgFeatureFlagResponse{Code: http.StatusForbidden}
		consistentIgnores := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
		assert.False(t, consistentIgnores)
	})

	t.Run("Feature Flag not available due to error", func(t *testing.T) {
		config.Unset(configuration.ORGANIZATION)
		consistentIgnores := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
		assert.False(t, consistentIgnores)
	})

	t.Run("Local Native Implementation Feature Flag set", func(t *testing.T) {
		config.Set(configuration.ORGANIZATION, orgId)
		responseNativeImpl = contract.OrgFeatureFlagResponse{Code: http.StatusOK, Ok: true}
		consistentIgnores := config.GetBool(configuration.FF_CODE_NATIVE_IMPLEMENTATION)
		assert.True(t, consistentIgnores)
	})
}

func Test_Code_UseNativeImplementation(t *testing.T) {
	logger := zerolog.Nop()

	// cciFeatureFlagEnabled bool, nativeImplementationFeatureFlag bool, ignoresFeatureFlag bool
	t.Run("cci feature flag disabled, native implementation disabled", func(t *testing.T) {
		expected := false
		config := configuration.NewWithOpts()
		config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, false)
		config.Set(configuration.FF_CODE_NATIVE_IMPLEMENTATION, false)
		config.Set(code_workflow.ConfigurarionSlceEnabled, false)
		actual := useNativeImplementation(config, &logger, true)
		assert.Equal(t, expected, actual)
	})

	t.Run("cci feature flag disabled, native implementation enabled", func(t *testing.T) {
		expected := true
		config := configuration.NewWithOpts()
		config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, false)
		config.Set(configuration.FF_CODE_NATIVE_IMPLEMENTATION, true)
		config.Set(code_workflow.ConfigurarionSlceEnabled, false)
		actual := useNativeImplementation(config, &logger, true)
		assert.Equal(t, expected, actual)
	})

	t.Run("cci feature flag enabled, native implementation disabled", func(t *testing.T) {
		expected := true
		config := configuration.NewWithOpts()
		config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, true)
		config.Set(configuration.FF_CODE_NATIVE_IMPLEMENTATION, false)
		config.Set(code_workflow.ConfigurarionSlceEnabled, false)
		actual := useNativeImplementation(config, &logger, true)
		assert.Equal(t, expected, actual)
	})

	t.Run("cci feature flag enabled, native implementation enabled", func(t *testing.T) {
		expected := true
		config := configuration.NewWithOpts()
		config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, true)
		config.Set(configuration.FF_CODE_NATIVE_IMPLEMENTATION, true)
		config.Set(code_workflow.ConfigurarionSlceEnabled, false)
		actual := useNativeImplementation(config, &logger, true)
		assert.Equal(t, expected, actual)
	})

	t.Run("cci feature flag enabled, native implementation enabled but scle enabled", func(t *testing.T) {
		expected := false
		config := configuration.NewWithOpts()
		config.Set(configuration.FF_CODE_CONSISTENT_IGNORES, true)
		config.Set(configuration.FF_CODE_NATIVE_IMPLEMENTATION, true)
		config.Set(code_workflow.ConfigurarionSlceEnabled, true)
		actual := useNativeImplementation(config, &logger, true)
		assert.Equal(t, expected, actual)
	})
}

// setupMockEngine creates a mock engine with basic expectations
func setupMockEngine(t *testing.T) *mocks.MockEngine {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := configuration.New()
	return setupMockEngineWithConfig(t, ctrl, config, false)
}

// setupMockEngineWithConfig creates a mock engine with the given configuration
func setupMockEngineWithConfig(t *testing.T, ctrl *gomock.Controller, config configuration.Configuration, withNetworkAccess bool) *mocks.MockEngine {
	t.Helper()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&zerolog.Logger{}).AnyTimes()

	if withNetworkAccess {
		mockEngine.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()
	}

	return mockEngine
}

// setupMockServerForSastSettings creates a mock HTTP server that returns SAST settings
func setupMockServerForSastSettings(t *testing.T, sastEnabled, localCodeEngineEnabled bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "/v1/cli-config/settings/sast") {
			response := &sast_contract.SastResponse{
				SastEnabled: sastEnabled,
				LocalCodeEngine: sast_contract.LocalCodeEngine{
					Enabled: localCodeEngineEnabled,
				},
			}
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}
	}))
}

// setupMockServerWithError creates a mock HTTP server that returns an error
func setupMockServerWithError(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

// setupMockEngineWithServer creates a mock engine configured with a test server
func setupMockEngineWithServer(t *testing.T, server *httptest.Server) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := configuration.New()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.ORGANIZATION, "test-org")

	mockEngine := setupMockEngineWithConfig(t, ctrl, config, true)
	return mockEngine, config
}

func Test_getSastSettingsConfig(t *testing.T) {
	t.Run("callback returns existing value when provided", func(t *testing.T) {
		existingValue := &sast_contract.SastResponse{SastEnabled: true}

		mockEngine := setupMockEngine(t)
		result, err := getSastSettingsConfig(mockEngine)(mockEngine.GetConfiguration(), existingValue)
		assert.NoError(t, err)
		assert.Equal(t, existingValue, result, "Should return existing value when provided")
	})

	t.Run("callback fetches settings when existing value is nil", func(t *testing.T) {
		server := setupMockServerForSastSettings(t, true, true)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := getSastSettingsConfig(mockEngine)(config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		sastResponse, ok := result.(*sast_contract.SastResponse)
		assert.True(t, ok, "result should be of type *sast_contract.SastResponse")
		assert.True(t, sastResponse.SastEnabled)
		assert.True(t, sastResponse.LocalCodeEngine.Enabled)
	})

	t.Run("adds organization dependency and clears cache on org change", func(t *testing.T) {
		testutils.CheckCacheRespectOrgDependency(
			t,
			code_workflow.ConfigurationSastSettings,
			func(isFirstCall bool) any {
				return &sast_contract.SastResponse{
					SastEnabled:     isFirstCall,
					LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: isFirstCall},
				}
			},
			InitCodeWorkflow,
			&sast_contract.SastResponse{
				SastEnabled:     true,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: true},
			},
			&sast_contract.SastResponse{
				SastEnabled:     false,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
			},
		)
	})

	t.Run("callback returns error when API call fails and existing value is nil", func(t *testing.T) {
		server := setupMockServerWithError(t)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := getSastSettingsConfig(mockEngine)(config, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("uses cloned config's org, API URL and network access", func(t *testing.T) {
		globalOrg := "00000000-0000-0000-0000-000000000001"
		clonedOrg := "00000000-0000-0000-0000-000000000002"
		globalAPIEndpoint := "https://api.snyk.io"
		cloneAPIEndpoint := "https://api.eu.snyk.io"

		// Track which org IDs and API URLs were requested
		var requestedOrgs []string
		var requestedAPIs []string

		httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
			// Extract org from query string and API URL from request
			org := req.URL.Query().Get("org")
			apiUrl := "https://" + req.Host
			requestedOrgs = append(requestedOrgs, org)
			requestedAPIs = append(requestedAPIs, apiUrl)

			response := &sast_contract.SastResponse{
				SastEnabled: org == globalOrg, // Mock a different response per org
				LocalCodeEngine: sast_contract.LocalCodeEngine{
					Enabled: apiUrl == globalAPIEndpoint, // Mock a different response per API URL
				},
			}
			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
			}
		})

		ctrl := gomock.NewController(t)
		mockEngine := mocks.NewMockEngine(ctrl)
		mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
		logger := zerolog.Logger{}

		config := configuration.NewInMemory()
		config.Set(configuration.API_URL, globalAPIEndpoint)
		config.Set(configuration.ORGANIZATION, globalOrg)

		mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
		mockEngine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
		mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
		mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
		mockNetworkAccess.EXPECT().Clone().Return(mockNetworkAccess).AnyTimes()
		mockNetworkAccess.EXPECT().SetConfiguration(gomock.Any()).AnyTimes()

		err := InitCodeWorkflow(mockEngine)
		require.NoError(t, err)
		assert.Len(t, requestedOrgs, 0, "Not expecting any requests before the first fetch")
		assert.Len(t, requestedAPIs, 0, "Not expecting any requests before the first fetch")

		// Fetch SAST settings from global config
		result1, err := config.GetWithError(code_workflow.ConfigurationSastSettings)
		require.NoError(t, err)
		sastResponse1, ok := result1.(*sast_contract.SastResponse)
		require.True(t, ok, "Response should be a SastResponse")
		assert.True(t, sastResponse1.SastEnabled, "Expecting globalOrg to have SAST enabled, since that is what we mocked it to be")
		assert.True(t, sastResponse1.LocalCodeEngine.Enabled, "Expecting globalAPIEndpoint to have local code engine enabled, since that is what we mocked it to be")
		assert.Equal(t, []string{globalOrg}, requestedOrgs, "First fetch should use globalOrg")
		assert.Equal(t, []string{globalAPIEndpoint}, requestedAPIs, "First fetch should use globalAPIEndpoint")

		// Clone config and change both org and API URL
		clonedConfig := config.Clone()
		clonedConfig.Set(configuration.ORGANIZATION, clonedOrg)
		clonedConfig.Set(configuration.API_URL, cloneAPIEndpoint)
		assert.Len(t, requestedOrgs, 1, "Cloning and setting values should not make requests")
		assert.Len(t, requestedAPIs, 1, "Cloning and setting values should not make requests")

		// Fetch SAST settings from cloned config
		result2, err := clonedConfig.GetWithError(code_workflow.ConfigurationSastSettings)
		require.NoError(t, err)
		sastResponse2, ok := result2.(*sast_contract.SastResponse)
		require.True(t, ok, "Response should be a SastResponse")
		assert.False(t, sastResponse2.SastEnabled, "Expecting clonedOrg to have SAST disabled, since that is what we mocked it to be")
		assert.False(t, sastResponse2.LocalCodeEngine.Enabled, "Expecting clonedAPIEndpoint to have local code engine disabled, since that is what we mocked it to be")
		assert.Equal(t, []string{globalOrg, clonedOrg}, requestedOrgs, "Second fetch should use clonedOrg")
		assert.Equal(t, []string{globalAPIEndpoint, cloneAPIEndpoint}, requestedAPIs, "Second fetch should use cloneAPIEndpoint")
	})
}

func Test_getSastEnabled(t *testing.T) {
	t.Run("callback function returns existing value when provided", func(t *testing.T) {
		mockEngine := setupMockEngine(t)
		result, err := getSastEnabled(mockEngine)(mockEngine.GetConfiguration(), true)
		assert.NoError(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.True(t, boolResult, "Should return existing value when provided")
	})

	t.Run("callback reads from ConfigurationSastSettings (pre-cached) when existing value is nil", func(t *testing.T) {
		mockEngine := setupMockEngine(t)
		config := mockEngine.GetConfiguration()

		// Set ConfigurationSastSettings in config
		sastSettings := &sast_contract.SastResponse{
			SastEnabled:     true,
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
		}
		config.Set(code_workflow.ConfigurationSastSettings, sastSettings)

		result, err := getSastEnabled(mockEngine)(config, nil)
		assert.NoError(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.True(t, boolResult, "Should return SastEnabled from ConfigurationSastSettings")
	})

	t.Run("depends on ConfigurationSastSettings", func(t *testing.T) {
		testutils.CheckConfigCachesDependency(
			t,
			code_workflow.ConfigurationSastEnabled,
			code_workflow.ConfigurationSastSettings,
			getSastEnabled,
			&sast_contract.SastResponse{
				SastEnabled:     true,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
			},
			&sast_contract.SastResponse{
				SastEnabled:     false,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
			},
			true,
			false,
		)
	})

	t.Run("respects organization changes (full chain)", func(t *testing.T) {
		testutils.CheckCacheRespectOrgDependency(
			t,
			code_workflow.ConfigurationSastEnabled,
			func(isFirstCall bool) any {
				return &sast_contract.SastResponse{
					SastEnabled:     isFirstCall,
					LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
				}
			},
			InitCodeWorkflow,
			true,
			false,
		)
	})

	t.Run("callback returns false and error when API call fails and existing value is nil", func(t *testing.T) {
		server := setupMockServerWithError(t)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := getSastEnabled(mockEngine)(config, nil)
		assert.Error(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.False(t, boolResult, "Should return false when API call fails")
	})
}

func Test_getSlceEnabled(t *testing.T) {
	t.Run("callback function returns existing value when provided", func(t *testing.T) {
		mockEngine := setupMockEngine(t)
		result, err := getSlceEnabled(mockEngine)(mockEngine.GetConfiguration(), true)
		assert.NoError(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.True(t, boolResult, "Should return existing value when provided")
	})

	t.Run("callback reads from ConfigurationSastSettings (pre-cached) when existing value is nil", func(t *testing.T) {
		mockEngine := setupMockEngine(t)
		config := mockEngine.GetConfiguration()

		// Set ConfigurationSastSettings in config
		sastSettings := &sast_contract.SastResponse{
			SastEnabled:     false,
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: true},
		}
		config.Set(code_workflow.ConfigurationSastSettings, sastSettings)

		result, err := getSlceEnabled(mockEngine)(config, nil)
		assert.NoError(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.True(t, boolResult, "Should return LocalCodeEngine.Enabled from ConfigurationSastSettings")
	})

	t.Run("depends on ConfigurationSastSettings", func(t *testing.T) {
		testutils.CheckConfigCachesDependency(
			t,
			code_workflow.ConfigurarionSlceEnabled,
			code_workflow.ConfigurationSastSettings,
			getSlceEnabled,
			&sast_contract.SastResponse{
				SastEnabled:     false,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: true},
			},
			&sast_contract.SastResponse{
				SastEnabled:     false,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
			},
			true,
			false,
		)
	})

	t.Run("respects organization changes (full chain)", func(t *testing.T) {
		testutils.CheckCacheRespectOrgDependency(
			t,
			code_workflow.ConfigurarionSlceEnabled,
			func(isFirstCall bool) any {
				return &sast_contract.SastResponse{
					SastEnabled:     false,
					LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: isFirstCall},
				}
			},
			InitCodeWorkflow,
			true,
			false,
		)
	})

	t.Run("callback returns false and error when API call fails and existing value is nil", func(t *testing.T) {
		server := setupMockServerWithError(t)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := getSlceEnabled(mockEngine)(config, nil)
		assert.Error(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.False(t, boolResult, "Should return false when API call fails")
	})
}
