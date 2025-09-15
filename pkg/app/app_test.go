package app

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	zlog "github.com/rs/zerolog/log"
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	pkgMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

func createOAuthTokenWithAudience(t *testing.T, audience string) string {
	t.Helper()
	header := &jws.Header{}
	claims := &jws.ClaimSet{
		Aud: audience,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	accessToken, err := jws.Encode(header, claims, pk)
	assert.NoError(t, err)

	token := oauth2.Token{
		AccessToken: accessToken,
	}

	tokenBytes, err := json.Marshal(token)
	assert.NoError(t, err)

	return string(tokenBytes)
}

func Test_AddsDefaultFunctionForCustomConfigFiles(t *testing.T) {
	t.Run("should load default config files (without given command line)", func(t *testing.T) {
		localConfig := configuration.NewWithOpts()
		engine := CreateAppEngineWithOptions(WithConfiguration(localConfig))
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
		localConfig := configuration.NewWithOpts()
		engine := CreateAppEngineWithOptions(WithConfiguration(localConfig))
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
	localConfig := configuration.NewWithOpts()
	engine := CreateAppEngineWithOptions(WithConfiguration(localConfig))
	assert.NotNil(t, engine)

	err := engine.Init()
	assert.Nil(t, err)

	expectApiUrl := constants.SNYK_DEFAULT_API_URL
	actualApiUrl := engine.GetConfiguration().GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)
}

func Test_CreateAppEngine_config_replaceV1inApi(t *testing.T) {
	localConfig := configuration.NewWithOpts()
	engine := CreateAppEngineWithOptions(WithConfiguration(localConfig))
	assert.NotNil(t, engine)

	err := engine.Init()
	assert.Nil(t, err)

	config := engine.GetConfiguration()

	expectApiUrl := "https://api.somehost:2134"
	config.Set(configuration.API_URL, expectApiUrl+"/v1")

	actualApiUrl := config.GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)
}

func Test_EnsureAuthConfigurationPrecedence(t *testing.T) {
	tests := []struct {
		name              string
		patPayload        string
		oauthJWTPayload   string
		userDefinedApiUrl interface{}
		expectedURL       string
	}{
		{
			name:              "no user-specified input, should default to the hard-coded default URL",
			patPayload:        "",
			oauthJWTPayload:   "",
			userDefinedApiUrl: "",
			expectedURL:       constants.SNYK_DEFAULT_API_URL,
		},
		{
			name:              "broken user-defined API URL is defined, should default to the hard-coded default URL",
			patPayload:        "",
			oauthJWTPayload:   "",
			userDefinedApiUrl: 123,
			expectedURL:       constants.SNYK_DEFAULT_API_URL,
		},
		{
			name:              "only user-defined API URL is defined, use that",
			patPayload:        "",
			oauthJWTPayload:   "",
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.user",
		},
		{
			name:              "with a broken PAT configured and a user-defined API URL, user-defined API URL should take precedence",
			patPayload:        `{broken`,
			oauthJWTPayload:   "",
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.user",
		},
		{
			name:              "with an empty PAT configured and a user-defined API URL, user-defined API URL should take precedence",
			patPayload:        `{}`,
			oauthJWTPayload:   "",
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.user",
		},
		{
			name:              "with a PAT configured and a user-defined API URL, PAT host should take precedence",
			patPayload:        `{"h":"api.snyk.io"}`,
			oauthJWTPayload:   "",
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.snyk.io",
		},
		{
			name:              "with a broken OAuth with no host configured and a user-defined API URL, user-defined API URL should take precedence",
			patPayload:        "",
			oauthJWTPayload:   `{broken`,
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.user",
		},
		{
			name:              "with OAuth with no host configured and a user-defined API URL, user-defined API URL should take precedence",
			patPayload:        "",
			oauthJWTPayload:   `{"sub":"1234567890","name":"John Doe","iat":1516239022,"aud":[]}`,
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.user",
		},
		{
			name:              "with OAuth configured and a user-defined API URL, OAuth audience should take precedence",
			patPayload:        "",
			oauthJWTPayload:   `{"sub":"1234567890","name":"John Doe","iat":1516239022,"aud":["https://api.oauth"]}`,
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.oauth",
		},
		{
			name:              "with only PAT configured, use PAT host",
			patPayload:        `{"h":"api.eu.snyk.io"}`,
			oauthJWTPayload:   "",
			userDefinedApiUrl: "",
			expectedURL:       "https://api.eu.snyk.io",
		},
		{
			name:              "with only OAuth configured, use OAuth audience",
			patPayload:        "",
			oauthJWTPayload:   `{"sub":"1234567890","name":"John Doe","iat":1516239022,"aud":["https://api.oauth"]}`,
			userDefinedApiUrl: "",
			expectedURL:       "https://api.oauth",
		},
		// This is not a likely scenario, as you cannot define both at the same time. However, it will potentially
		// catch regressions if this test starts to fail.
		{
			name:              "with PAT, OAuth and user-defined API URL, PAT should take precedence over OAuth",
			patPayload:        `{"h":"api.au.snyk.io"}`,
			oauthJWTPayload:   `{"sub":"1234567890","name":"John Doe","iat":1516239022,"aud":["https://api.oauth"]}`,
			userDefinedApiUrl: "https://api.user",
			expectedURL:       "https://api.au.snyk.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			engine := CreateAppEngineWithOptions(WithConfiguration(config))
			assert.NotNil(t, engine)

			if tt.userDefinedApiUrl != "" {
				config.Set(configuration.API_URL, tt.userDefinedApiUrl)
			}

			if tt.patPayload != "" {
				pat := createMockPAT(t, tt.patPayload)
				config.Set(configuration.AUTHENTICATION_TOKEN, pat)
			}

			if tt.oauthJWTPayload != "" {
				jwtHeader := `{"alg":"HS256","typ":"JWT"}`
				encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))
				encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(tt.oauthJWTPayload))
				signature := "hWq0fKukObQSkphAdyEC7-m4jXIb4VdWyQySmmgy0GU"

				jwtToken := fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature)
				oauthTokenJSON := fmt.Sprintf(`{"access_token": "%s"}`, jwtToken)

				config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, oauthTokenJSON)
			}

			actualApiUrl := config.GetString(configuration.API_URL)
			assert.Equal(t, tt.expectedURL, actualApiUrl)
		})
	}
}

func Test_CreateAppEngine_config_PAT_autoRegionDetection(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		apiUrl := "api.snyk.io"
		euPAT := createMockPAT(t, fmt.Sprintf(`{"h":"%s"}`, apiUrl))
		config := configuration.NewWithOpts()
		engine := CreateAppEngineWithOptions(WithConfiguration(config))
		assert.NotNil(t, engine)

		config.Set(configuration.AUTHENTICATION_TOKEN, euPAT)

		actualApiUrl := config.GetString(configuration.API_URL)
		assert.Equal(t, fmt.Sprintf("https://%s", apiUrl), actualApiUrl)
	})

	t.Run("eu", func(t *testing.T) {
		apiUrl := "api.eu.snyk.io"
		euPAT := createMockPAT(t, fmt.Sprintf(`{"h":"%s"}`, apiUrl))
		config := configuration.NewWithOpts()
		engine := CreateAppEngineWithOptions(WithConfiguration(config))
		assert.NotNil(t, engine)

		config.Set(configuration.AUTHENTICATION_TOKEN, euPAT)

		actualApiUrl := config.GetString(configuration.API_URL)
		assert.Equal(t, fmt.Sprintf("https://%s", apiUrl), actualApiUrl)
	})

	t.Run("invalid PAT reverts to default API URL (with wrong payload)", func(t *testing.T) {
		patWithExtraSegments := "snyk_uat.12345678.payload.signature.extra"
		config := configuration.NewWithOpts()
		engine := CreateAppEngineWithOptions(WithConfiguration(config))
		assert.NotNil(t, engine)

		config.Set(configuration.AUTHENTICATION_TOKEN, patWithExtraSegments)

		actualApiUrl := config.GetString(configuration.API_URL)
		assert.Equal(t, constants.SNYK_DEFAULT_API_URL, actualApiUrl)
	})

	t.Run("invalid PAT reverts to default API URL (with no hostname in claim)", func(t *testing.T) {
		pat := createMockPAT(t, `{}`)
		config := configuration.NewWithOpts()
		engine := CreateAppEngineWithOptions(WithConfiguration(config))
		assert.NotNil(t, engine)

		config.Set(configuration.AUTHENTICATION_TOKEN, pat)

		actualApiUrl := config.GetString(configuration.API_URL)
		assert.Equal(t, constants.SNYK_DEFAULT_API_URL, actualApiUrl)
	})
}

func Test_CreateAppEngine_config_OauthAudHasPrecedence(t *testing.T) {
	config := configuration.New()
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN,
		// JWT generated at https://jwt.io with claim:
		//   "aud": ["https://api.example.com"]
		`{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOlsiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iXX0.hWq0fKukObQSkphAdyEC7-m4jXIb4VdWyQySmmgy0GU"}`,
	)
	logger := log.New(os.Stderr, "", 0)

	t.Run("Audience claim takes precedence of configured value", func(t *testing.T) {
		expectedApiUrl := "https://api.example.com"
		localConfig := config.Clone()
		localConfig.Set(configuration.API_URL, "https://api.dev.snyk.io")

		engine := CreateAppEngineWithOptions(WithConfiguration(localConfig), WithLogger(logger))
		assert.NotNil(t, engine)

		actualApiUrl := localConfig.GetString(configuration.API_URL)
		assert.Equal(t, expectedApiUrl, actualApiUrl)
	})

	t.Run("nothing configured", func(t *testing.T) {
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

func Test_initConfiguration_failDefaultOrgLookup(t *testing.T) {
	orgId := "someOrgId"
	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetDefaultOrgId().Return("", errors.New("error")).Times(2)
	mockApiClient.EXPECT().GetDefaultOrgId().Return(orgId, nil).Times(1)

	config := configuration.NewWithOpts(configuration.WithCachingEnabled(10 * time.Second))
	engine := workflow.NewWorkFlowEngine(config)
	apiClientFactory := func(url string, client *http.Client) api.ApiClient {
		return mockApiClient
	}
	initConfiguration(engine, config, &zlog.Logger, apiClientFactory)

	actualOrgId, orgIdError := config.GetStringWithError(configuration.ORGANIZATION)
	assert.Error(t, orgIdError)
	assert.Empty(t, actualOrgId)

	actualOrgSlug, slugError := config.GetStringWithError(configuration.ORGANIZATION_SLUG)
	assert.Error(t, slugError)
	assert.Empty(t, actualOrgSlug)

	// ensure that if the error resolves, a valid value is returned
	actualOrgId, orgIdError = config.GetStringWithError(configuration.ORGANIZATION)
	assert.NoError(t, orgIdError)
	assert.Equal(t, orgId, actualOrgId)
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

func createMockPAT(t *testing.T, payload string) string {
	t.Helper()

	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := "signature"
	return fmt.Sprintf("snyk_uat.12345678.%s.%s", encodedPayload, signature)
}

func TestDefaultInputDirectory(t *testing.T) {
	defaultFunction := defaultInputDirectory()
	assert.NotNil(t, defaultFunction)

	// Create a mock configuration for testing
	mockConfig := configuration.New()

	tests := []struct {
		name           string
		existingValue  interface{}
		expectedError  bool
		expectedResult interface{}
		description    string
	}{
		{
			name:           "nil input",
			existingValue:  nil,
			expectedError:  false,
			expectedResult: nil, // Will fall back to current working directory
			description:    "should handle nil input gracefully and return current working directory",
		},
		{
			name:           "empty string",
			existingValue:  "",
			expectedError:  false,
			expectedResult: nil, // Will fall back to current working directory
			description:    "should handle empty string and return current working directory",
		},
		{
			name:           "whitespace only string",
			existingValue:  "   \t\n  ",
			expectedError:  false,
			expectedResult: nil, // Will fall back to current working directory after trimming
			description:    "should handle whitespace-only string and return current working directory",
		},
		{
			name:           "valid absolute path",
			existingValue:  "/usr/local/bin",
			expectedError:  false,
			expectedResult: "/usr/local/bin",
			description:    "should return valid absolute path as-is",
		},
		{
			name:           "valid relative path",
			existingValue:  "./relative/path",
			expectedError:  false,
			expectedResult: "./relative/path",
			description:    "should return valid relative path as-is",
		},
		{
			name:           "path with leading/trailing whitespace",
			existingValue:  "  /path/with/whitespace  ",
			expectedError:  false,
			expectedResult: "  /path/with/whitespace  ",
			description:    "should preserve whitespace and return path exactly as provided",
		},
		{
			name:           "non-string type - integer",
			existingValue:  123,
			expectedError:  false,
			expectedResult: nil, // Will fall back to current working directory
			description:    "should handle non-string types gracefully and return current working directory",
		},
		{
			name:           "non-string type - boolean",
			existingValue:  true,
			expectedError:  false,
			expectedResult: nil, // Will fall back to current working directory
			description:    "should handle non-string types gracefully and return current working directory",
		},
		{
			name:           "non-string type - slice",
			existingValue:  []string{"path1", "path2"},
			expectedError:  false,
			expectedResult: []string{"path1", "path2"},
			description:    "should handle non-string types gracefully and return the slice as there are multiple paths possible",
		},
		{
			name:           "non-string type - slice with empty strings",
			existingValue:  []string{"path1", "", "path2"},
			expectedError:  false,
			expectedResult: []string{"path1", "path2"},
			description:    "should ignore empty strings in slices",
		},
		{
			name:           "non-string type - map",
			existingValue:  map[string]string{"key": "value"},
			expectedError:  false,
			expectedResult: nil, // Will fall back to current working directory
			description:    "should handle non-string types gracefully and return current working directory",
		},
		{
			name:           "current directory symbol",
			existingValue:  ".",
			expectedError:  false,
			expectedResult: ".",
			description:    "should return current directory symbol as-is",
		},
		{
			name:           "parent directory symbol",
			existingValue:  "..",
			expectedError:  false,
			expectedResult: "..",
			description:    "should return parent directory symbol as-is",
		},
		{
			name:           "home directory symbol",
			existingValue:  "~",
			expectedError:  false,
			expectedResult: "~",
			description:    "should return home directory symbol as-is",
		},
		{
			name:           "path with special characters",
			existingValue:  "/path/with/special-chars_123",
			expectedError:  false,
			expectedResult: "/path/with/special-chars_123",
			description:    "should handle paths with special characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := defaultFunction(mockConfig, tt.existingValue)

			// Check error expectations
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Check result expectations
			if tt.expectedResult != nil {
				// For specific expected results, check exact match
				assert.Equal(t, tt.expectedResult, result, tt.description)
			} else {
				// For fallback cases, just ensure we get a non-empty result
				assert.NotNil(t, result, tt.description)
				if str, ok := result.(string); ok {
					assert.NotEmpty(t, str, tt.description)
				} else {
					assert.Fail(t, "result is not a string", tt.description)
				}
			}
		})
	}

	// Additional test to verify the function actually returns a function
	t.Run("returns callable function", func(t *testing.T) {
		assert.IsType(t, defaultFunction, defaultFunction)
	})
}

func Test_auth_oauth(t *testing.T) {
	mockCtl := gomock.NewController(t)
	config := configuration.NewWithOpts()
	engine := CreateAppEngineWithOptions(WithConfiguration(config))
	assert.NotNil(t, engine)

	logger := engine.GetLogger()
	analytics := analytics.New()

	t.Run("oauth token is set on global config", func(t *testing.T) {
		// Create separate configs for invocation and global
		globalConfig := engine.GetConfiguration()
		invocationConfig := globalConfig.Clone()

		// Expected OAuth token that will be set after authentication
		expectedOAuthToken := "test-oauth-token-12345"

		invocationConfig.Set(localworkflows.AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

		// Create mocks
		mockInvocationContext := pkgMocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(invocationConfig).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()
		mockInvocationContext.EXPECT().GetEngine().Return(engine).AnyTimes()

		mockAuthenticator := pkgMocks.NewMockAuthenticator(mockCtl)
		mockAuthenticator.EXPECT().Authenticate().DoAndReturn(func() error {
			// Simulate successful OAuth authentication by setting the token
			invocationConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, expectedOAuthToken)
			return nil
		})

		// Execute the auth workflow
		err := localworkflows.AuthEntryPointDI(mockInvocationContext, logger, engine, mockAuthenticator)
		assert.NoError(t, err)

		// Verify that the OAuth token was set on the global config
		actualToken := globalConfig.Get(auth.CONFIG_KEY_OAUTH_TOKEN)
		assert.Equal(t, expectedOAuthToken, actualToken, "OAuth token should be set on global config after successful authentication")

		// Verify that the authentication token is not set (should be cleared)
		assert.Empty(t, globalConfig.GetString(configuration.AUTHENTICATION_TOKEN), "Legacy authentication token should be cleared")
	})

	t.Run("oauth token change updates api url extraction", func(t *testing.T) {
		globalConfig := engine.GetConfiguration()
		globalConfig.Set(configuration.API_URL, "https://api.snyk.io")
		invocationConfig := globalConfig.Clone()

		firstAPIURL := "https://api.eu.snyk.io"
		firstOAuthToken := createOAuthTokenWithAudience(t, firstAPIURL)

		// Set auth type to OAuth
		invocationConfig.Set(localworkflows.AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

		// Create mocks
		mockInvocationContext := pkgMocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(invocationConfig).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()

		// First authentication with US token
		mockAuthenticator := pkgMocks.NewMockAuthenticator(mockCtl)
		mockAuthenticator.EXPECT().Authenticate().DoAndReturn(func() error {
			invocationConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, firstOAuthToken)
			return nil
		})

		// Execute first auth workflow
		err := localworkflows.AuthEntryPointDI(mockInvocationContext, logger, engine, mockAuthenticator)
		assert.NoError(t, err)

		// Verify first OAuth token was set
		actualToken := globalConfig.GetString(auth.CONFIG_KEY_OAUTH_TOKEN)
		assert.Equal(t, firstOAuthToken, actualToken)

		actualApiUrl := globalConfig.GetString(configuration.API_URL)
		assert.Equal(t, firstAPIURL, actualApiUrl, "First OAuth token should contain EU API URL")

		// Now simulate re-authentication with EU
		secondAPIURL := "https://api.us.snyk.io"
		secondOAuthToken := createOAuthTokenWithAudience(t, secondAPIURL)

		// Mock second authentication
		mockAuthenticator.EXPECT().Authenticate().DoAndReturn(func() error {
			invocationConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, secondOAuthToken)
			return nil
		})

		// Execute second workflow
		err = localworkflows.AuthEntryPointDI(mockInvocationContext, logger, engine, mockAuthenticator)
		assert.NoError(t, err)

		// Verify second OAuth token was set
		actualToken = globalConfig.GetString(auth.CONFIG_KEY_OAUTH_TOKEN)
		assert.Equal(t, secondOAuthToken, actualToken)

		// Extract and verify second API URL from token
		actualApiUrl = globalConfig.GetString(configuration.API_URL)
		assert.Equal(t, secondAPIURL, actualApiUrl, "Second OAuth token should contain US API URL")
	})
}

// this tests compares the behavior of the config when it has caching enabled and when it doesn't
func Test_config_compareCachedAndUncachedConfig(t *testing.T) {
	tests := []struct {
		name   string
		config configuration.Configuration
	}{
		{
			name:   "Cached config",
			config: configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour * 1)),
		},
		{
			name:   "Uncached config",
			config: configuration.NewWithOpts(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := CreateAppEngineWithOptions(WithConfiguration(tt.config))
			assert.NotNil(t, engine)

			// Default API URL
			assert.Equal(t, constants.SNYK_DEFAULT_API_URL, tt.config.GetString(configuration.API_URL))

			// set API URL explicitly
			tt.config.Set(configuration.API_URL, "https://api.us.snyk.io")
			assert.Equal(t, "https://api.us.snyk.io", tt.config.GetString(configuration.API_URL))
			assert.Equal(t, "https://app.us.snyk.io", tt.config.GetString(configuration.WEB_APP_URL))

			// set PAT and derive API URL
			tt.config.Set(configuration.AUTHENTICATION_TOKEN, createMockPAT(t, `{"h":"api.au.snyk.io"}`))
			assert.Equal(t, "https://api.au.snyk.io", tt.config.GetString(configuration.API_URL))
			assert.Equal(t, "https://app.au.snyk.io", tt.config.GetString(configuration.WEB_APP_URL))
			tt.config.Unset(configuration.AUTHENTICATION_TOKEN)

			// set OAuth token and derive API URL
			tt.config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, createOAuthTokenWithAudience(t, "https://api.snykgov.io"))
			assert.Equal(t, "https://api.snykgov.io", tt.config.GetString(configuration.API_URL))
			assert.Equal(t, "https://app.snykgov.io", tt.config.GetString(configuration.WEB_APP_URL))

			// set PAT and derive API URL
			tt.config.Set(configuration.AUTHENTICATION_TOKEN, createMockPAT(t, `{"h":"api.eu.snyk.io"}`))
			assert.Equal(t, "https://api.eu.snyk.io", tt.config.GetString(configuration.API_URL))
			assert.Equal(t, "https://app.eu.snyk.io", tt.config.GetString(configuration.WEB_APP_URL))

			// unset PAT and OAuth token
			tt.config.Unset(configuration.AUTHENTICATION_TOKEN)
			tt.config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)

			// exlicitly set API URL is restored
			assert.Equal(t, "https://api.us.snyk.io", tt.config.GetString(configuration.API_URL))
			assert.Equal(t, "https://app.us.snyk.io", tt.config.GetString(configuration.WEB_APP_URL))
		})
	}
}
