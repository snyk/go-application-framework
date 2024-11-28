package app

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golang/mock/gomock"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_AddsDefaultFunctionForCustomConfigFiles(t *testing.T) {
	t.Run("should load default config files (without given command line)", func(t *testing.T) {
		engine := CreateAppEngine()
		conf := engine.GetConfiguration()

		actual := conf.GetStringSlice(configuration.CUSTOM_CONFIG_FILES)
		assert.Lenf(t, actual, 5, "defaults not set")
		assert.Equal(t, ".snyk.env", actual[0])
		assert.Equal(t, ".envrc", actual[1])
		assert.Equal(t, ".snyk.env."+runtime.GOOS, actual[2])
		assert.Equal(t, ".envrc."+runtime.GOOS, actual[3])
		home, err := os.UserHomeDir()
		if err == nil {
			assert.Equal(t, filepath.Join(home, actual[0]), actual[4])
		}
	})

	t.Run("should load default config files (with given command line)", func(t *testing.T) {
		engine := CreateAppEngine()
		conf := engine.GetConfiguration()
		conf.Set("configfile", "abc/d")

		actual := conf.GetStringSlice(configuration.CUSTOM_CONFIG_FILES)
		assert.Lenf(t, actual, 6, "defaults not set")
		assert.Equal(t, ".snyk.env", actual[0])
		assert.Equal(t, ".envrc", actual[1])
		assert.Equal(t, ".snyk.env."+runtime.GOOS, actual[2])
		assert.Equal(t, ".envrc."+runtime.GOOS, actual[3])
		assert.Equal(t, "abc/d", actual[4])
		home, err := os.UserHomeDir()
		if err == nil {
			assert.Equal(t, filepath.Join(home, actual[0]), actual[5])
		}
	})
}

func Test_CreateAppEngine(t *testing.T) {
	engine := CreateAppEngine()
	assert.NotNil(t, engine)

	err := engine.Init()
	assert.Nil(t, err)

	expectApiUrl := constants.SNYK_DEFAULT_API_URL
	actualApiUrl := engine.GetConfiguration().GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)
}

func Test_CreateAppEngine_config_replaceV1inApi(t *testing.T) {
	engine := CreateAppEngine()
	assert.NotNil(t, engine)

	err := engine.Init()
	assert.Nil(t, err)

	config := engine.GetConfiguration()

	expectApiUrl := "https://api.somehost:2134"
	config.Set(configuration.API_URL, expectApiUrl+"/v1")

	actualApiUrl := config.GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)
}

func Test_CreateAppEngine_config_OauthAudHasPredence(t *testing.T) {
	config := configuration.New()
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN,
		// JWT generated at https://jwt.io with claim:
		//   "aud": ["https://api.example.com"]
		`{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOlsiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iXX0.hWq0fKukObQSkphAdyEC7-m4jXIb4VdWyQySmmgy0GU"}`,
	)
	logger := log.New(os.Stderr, "", 0)

	t.Run("", func(t *testing.T) {
		expectedApiUrl := "https://api.dev.snyk.io"
		localConfig := config.Clone()
		localConfig.Set(configuration.API_URL, expectedApiUrl)

		engine := CreateAppEngineWithOptions(WithConfiguration(localConfig), WithLogger(logger))
		assert.NotNil(t, engine)

		actualApiUrl := localConfig.GetString(configuration.API_URL)
		assert.Equal(t, expectedApiUrl, actualApiUrl)
	})

	t.Run("", func(t *testing.T) {
		expectedApiUrl := "https://api.example.com"
		localConfig := config.Clone()

		engine := CreateAppEngineWithOptions(WithConfiguration(localConfig), WithLogger(logger))
		assert.NotNil(t, engine)

		actualApiUrl := localConfig.GetString(configuration.API_URL)
		assert.Equal(t, expectedApiUrl, actualApiUrl)
	})

}

func Test_initConfiguration_updateDefaultOrgId(t *testing.T) {
	orgName := "someOrgName"
	orgId := "someOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetOrgIdFromSlug(orgName).Return(orgId, nil).AnyTimes()
	mockApiClient.EXPECT().GetSlugFromOrgId(orgId).Return(orgName, nil).AnyTimes()

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)

	config.Set(configuration.ORGANIZATION, orgName)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	actualOrgSlug := config.GetString(configuration.ORGANIZATION_SLUG)
	assert.Equal(t, orgId, actualOrgId)
	assert.Equal(t, orgName, actualOrgSlug)
}

func Test_initConfiguration_useDefaultOrg(t *testing.T) {
	defaultOrgId := "someDefaultOrgId"
	defaultOrgSlug := "someDefaultOrgSlug"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetDefaultOrgId().Return(defaultOrgId, nil).AnyTimes()
	mockApiClient.EXPECT().GetSlugFromOrgId(defaultOrgId).Return(defaultOrgSlug, nil).AnyTimes()

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	actualOrgSlug := config.GetString(configuration.ORGANIZATION_SLUG)
	assert.Equal(t, defaultOrgId, actualOrgId)
	assert.Equal(t, defaultOrgSlug, actualOrgSlug)
}

func Test_initConfiguration_useDefaultOrgAsFallback(t *testing.T) {
	orgName := "someOrgName"
	defaultOrgId := "someDefaultOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetOrgIdFromSlug(orgName).Return("", errors.New("Failed to fetch org id from slug")).AnyTimes()
	mockApiClient.EXPECT().GetDefaultOrgId().Return(defaultOrgId, nil).AnyTimes()
	mockApiClient.EXPECT().GetSlugFromOrgId(defaultOrgId).Return(orgName, nil).AnyTimes()

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)

	config.Set(configuration.ORGANIZATION, orgName)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	actualOrgSlug := config.GetString(configuration.ORGANIZATION_SLUG)
	assert.Equal(t, defaultOrgId, actualOrgId)
	assert.Equal(t, orgName, actualOrgSlug)
}

func Test_initConfiguration_uuidOrgId(t *testing.T) {
	orgId := "0d2bc57c-1df9-4115-996f-4f19aa12912b"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)
	config.Set(configuration.ORGANIZATION, orgId)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	assert.Equal(t, actualOrgId, orgId)
}

func Test_CreateAppEngineWithLogger(t *testing.T) {
	logger := &zlog.Logger

	engine := CreateAppEngineWithOptions(WithZeroLogger(logger))

	assert.NotNil(t, engine)
	assert.Equal(t, logger, engine.GetLogger())
}

func Test_CreateAppEngineWithConfigAndLoggerOptions(t *testing.T) {
	logger := &zlog.Logger
	config := configuration.NewInMemory()

	engine := CreateAppEngineWithOptions(WithZeroLogger(logger), WithConfiguration(config))

	assert.NotNil(t, engine)
	assert.Equal(t, logger, engine.GetLogger())
	assert.Equal(t, config, engine.GetConfiguration())
}

func Test_CreateAppEngineWithRuntimeInfo(t *testing.T) {
	ri := runtimeinfo.New(
		runtimeinfo.WithName("some-app"),
		runtimeinfo.WithVersion("some.version"))
	engine := CreateAppEngineWithOptions(WithRuntimeInfo(ri))

	assert.NotNil(t, engine)
	assert.Equal(t, ri, engine.GetRuntimeInfo())
}

func Test_initConfiguration_snykgov(t *testing.T) {
	endpoint := "https://snykgov.io"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	config := configuration.NewInMemory()
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(workflow.NewWorkFlowEngine(config), config, &zlog.Logger, apiClientFactory)

	config.Set(configuration.API_URL, endpoint)

	actualOAuthFF := config.GetBool(configuration.FF_OAUTH_AUTH_FLOW_ENABLED)
	assert.True(t, actualOAuthFF)

	isFedramp := config.GetBool(configuration.IS_FEDRAMP)
	assert.True(t, isFedramp)
}

func Test_initConfiguration_NOT_snykgov(t *testing.T) {
	endpoint := "https://api.eu.snyk.io"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	config := configuration.NewInMemory()
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(workflow.NewWorkFlowEngine(config), config, &zlog.Logger, apiClientFactory)

	config.Set(configuration.API_URL, endpoint)

	isFedramp := config.GetBool(configuration.IS_FEDRAMP)
	assert.False(t, isFedramp)
}

func Test_initConfiguration_PREVIEW_FEATURES_ENABLED(t *testing.T) {
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-preview.456")))

	actual := config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.True(t, actual)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-dev.456")))
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.True(t, actual)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-rc.456")))
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.False(t, actual)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3")))
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.False(t, actual)

	config.Set(configuration.PREVIEW_FEATURES_ENABLED, true)
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.True(t, actual)
}

func Test_initConfiguration_DEFAULT_TEMP_DIRECTORY(t *testing.T) {
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)

	//	setup mock
	mockCachePath := "someuser/caches"
	config.Set(configuration.CACHE_PATH, mockCachePath)
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)

	t.Run("version is not set", func(t *testing.T) {
		engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("")))
		expected := fmt.Sprint(mockCachePath, "/0.0.0", "/tmp/pid", os.Getpid())
		actual := config.GetString(configuration.TEMP_DIR_PATH)
		assert.Equal(t, expected, actual)
	})

	t.Run("Version is set", func(t *testing.T) {
		engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-preview.456")))
		expected := fmt.Sprint(mockCachePath, "/1.2.3-preview.456", "/tmp/pid", os.Getpid())
		actual := config.GetString(configuration.TEMP_DIR_PATH)
		assert.Equal(t, expected, actual)
	})

	t.Run("Custom temp path is set in config", func(t *testing.T) {
		customTempPath := "/custom/tmp/path"
		config.Set(configuration.TEMP_DIR_PATH, customTempPath)
		engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-preview.456")))
		expected := customTempPath
		actual := config.GetString(configuration.TEMP_DIR_PATH)
		assert.Equal(t, expected, actual)
	})
}
