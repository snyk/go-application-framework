package app

import (
	"crypto/fips140"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	"github.com/snyk/go-httpauth/pkg/httpauth"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	pkg_utils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func defaultFuncOrganizationSlug(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(configuration.ORGANIZATION_SLUG, configuration.ORGANIZATION)
	if err != nil {
		logger.Print("Failed to add dependency for ORGANIZATION_SLUG:", err)
	}

	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		orgId := config.GetString(configuration.ORGANIZATION)
		if len(orgId) == 0 {
			return existingValue, nil
		}
		slugName, err := apiClient.GetSlugFromOrgId(orgId)
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION_SLUG\":", err)
		}
		return slugName, nil
	}
	return callback
}

func defaultFuncOrganization(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(configuration.ORGANIZATION, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for ORGANIZATION:", err)
	}

	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		existingString, ok := existingValue.(string)
		if existingValue != nil && ok && len(existingString) > 0 {
			orgId := existingString
			_, err := uuid.Parse(orgId)
			isSlugName := err != nil
			if isSlugName {
				orgId, err = apiClient.GetOrgIdFromSlug(existingString)
				if err != nil {
					logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
				} else {
					return orgId, nil
				}
			} else {
				return orgId, nil
			}
		}

		orgId, err := apiClient.GetDefaultOrgId()
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		}

		return orgId, err
	}
	return callback
}

func defaultFuncApiUrl(globalConfig configuration.Configuration, logger *zerolog.Logger) configuration.DefaultValueFunction {
	err := globalConfig.AddKeyDependency(configuration.API_URL, configuration.AUTHENTICATION_TOKEN)
	if err != nil {
		logger.Print("Failed to add dependency for API_URL:", err)
	}
	err = globalConfig.AddKeyDependency(configuration.API_URL, auth.CONFIG_KEY_OAUTH_TOKEN)
	if err != nil {
		logger.Print("Failed to add dependency for API_URL:", err)
	}

	callback := func(config configuration.Configuration, existingValue interface{}) (interface{}, error) {
		urlString := constants.SNYK_DEFAULT_API_URL
		authToken := config.GetString(configuration.AUTHENTICATION_TOKEN)

		// If a user specified their own value, start by respecting that
		if existingValue != nil {
			if temp, ok := existingValue.(string); ok {
				urlString = temp
			}
		}

		// If an oauth token is provided, with a URL in the audience claim, use that instead
		urlFromOauthToken, err := auth.GetAudienceClaimFromOauthToken(config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
		if err != nil {
			logger.Warn().Err(err).Msg("failed to read oauth token")
		}

		if len(urlFromOauthToken) > 0 && len(urlFromOauthToken[0]) > 0 {
			urlString = urlFromOauthToken[0]
		}

		// Same logic for PAT - if a PAT is provided, and it has a URL in the claims, use that instead
		if auth.IsAuthTypePAT(authToken) {
			apiUrl, claimsErr := auth.GetApiUrlFromPAT(authToken)
			if claimsErr != nil {
				logger.Warn().Err(claimsErr).Msg("failed to get api url from pat")
			}
			if len(apiUrl) > 0 {
				urlString = apiUrl
			}
		}

		apiString, err := api.GetCanonicalApiUrlFromString(urlString)
		if err != nil {
			logger.Warn().Err(err).Str(configuration.API_URL, urlString).Msg("failed to get api url")
		}
		return apiString, nil
	}
	return callback
}

func defaultInputDirectory() configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		// Check if we have a valid string value
		existingString, isString := existingValue.(string)
		if isString && len(existingString) > 0 {
			// Return the string value as-is (preserving any whitespace)
			return existingString, nil
		}

		existingStringSlice, isStringSlice := existingValue.([]string)
		resultingSlice := []string{}
		for _, s := range existingStringSlice {
			if len(s) > 0 {
				resultingSlice = append(resultingSlice, s)
			}
		}

		if isStringSlice && len(resultingSlice) > 0 {
			// Return the string value as-is (preserving any whitespace)
			return resultingSlice, nil
		}

		// Fall back to current working directory for non-string types or empty strings
		path, err := os.Getwd()
		if err != nil {
			return ".", err
		}
		return path, nil
	}
	return callback
}

func defaultTempDirectory(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		version := "0.0.0"
		ri := engine.GetRuntimeInfo()
		if ri != nil && len(ri.GetVersion()) > 0 {
			version = ri.GetVersion()
		}

		if existingValue != nil {
			existingString, ok := existingValue.(string)
			if ok {
				err := pkg_utils.CreateAllDirectories(existingString, version)
				if err != nil {
					logger.Err(err)
				}
			}

			return existingValue, nil
		}

		tmpDir := pkg_utils.GetTemporaryDirectory(config.GetString(configuration.CACHE_PATH), version)
		err := pkg_utils.CreateAllDirectories(tmpDir, version)
		if err != nil {
			logger.Err(err)
		}

		return tmpDir, nil
	}
	return callback
}

func defaultPreviewFeaturesEnabled(engine workflow.Engine) configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue != nil {
			return existingValue, nil
		}

		ri := engine.GetRuntimeInfo()
		if ri == nil {
			return false, nil
		}

		version := ri.GetVersion()

		if strings.Contains(version, "-preview") || strings.Contains(version, "-dev") {
			return true, nil
		}

		return false, nil
	}
	return callback
}

func defaultMaxNetworkRetryAttempts(engine workflow.Engine) configuration.DefaultValueFunction {
	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		const multipleAttempts = 3 // three here is chosen based on other places in the application
		const singleAttempt = 1

		if existingValue != nil {
			return existingValue, nil
		}

		if engine.GetConfiguration().GetBool(configuration.PREVIEW_FEATURES_ENABLED) {
			return multipleAttempts, nil
		}
		return singleAttempt, nil
	}
	return callback
}

// initConfiguration initializes the configuration with initial values.
func initConfiguration(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) {
	if logger == nil {
		logger = &zlog.Logger
	}
	if apiClientFactory == nil {
		apiClientFactory = func(url string, client *http.Client) api.ApiClient {
			return api.NewApi(url, client)
		}
	}

	dir, err := utils.SnykCacheDir()
	if err != nil {
		logger.Print("Failed to determine cache directory:", err)
	}

	config.AddDefaultValue(configuration.ANALYTICS_DISABLED, configuration.StandardDefaultValueFunction(false))
	config.AddDefaultValue(configuration.WORKFLOW_USE_STDIO, configuration.StandardDefaultValueFunction(false))
	config.AddDefaultValue(configuration.PROXY_AUTHENTICATION_MECHANISM, configuration.StandardDefaultValueFunction(httpauth.StringFromAuthenticationMechanism(httpauth.AnyAuth)))
	config.AddDefaultValue(configuration.CACHE_PATH, configuration.StandardDefaultValueFunction(dir))
	config.AddDefaultValue(configuration.AUTHENTICATION_SUBDOMAINS, configuration.StandardDefaultValueFunction([]string{"deeproxy"}))
	config.AddDefaultValue(configuration.MAX_THREADS, configuration.StandardDefaultValueFunction(runtime.NumCPU()))
	config.AddDefaultValue(presenters.CONFIG_JSON_STRIP_WHITESPACES, configuration.StandardDefaultValueFunction(true))
	config.AddDefaultValue(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP, configuration.StandardDefaultValueFunction(constants.SNYK_DEFAULT_ALLOWED_HOST_REGEXP))

	// set default filesize threshold to 512MB
	config.AddDefaultValue(configuration.IN_MEMORY_THRESHOLD_BYTES, configuration.StandardDefaultValueFunction(constants.SNYK_DEFAULT_IN_MEMORY_THRESHOLD_MB))
	config.AddDefaultValue(configuration.TEMP_DIR_PATH, defaultTempDirectory(engine, config, logger))

	config.AddDefaultValue(configuration.API_URL, defaultFuncApiUrl(config, logger))

	err = config.AddKeyDependency(configuration.WEB_APP_URL, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for WEB_APP_URL:", err)
	}

	config.AddDefaultValue(configuration.WEB_APP_URL, func(c configuration.Configuration, existingValue any) (any, error) {
		canonicalApiUrl := c.GetString(configuration.API_URL)
		appUrl, appUrlErr := api.DeriveAppUrl(canonicalApiUrl)
		if appUrlErr != nil {
			logger.Print("Failed to determine default value for \"WEB_APP_URL\":", appUrlErr)
		}

		return appUrl, nil
	})

	config.AddDefaultValue(configuration.ORGANIZATION, defaultFuncOrganization(engine, config, logger, apiClientFactory))
	config.AddDefaultValue(configuration.ORGANIZATION_SLUG, defaultFuncOrganizationSlug(engine, config, logger, apiClientFactory))

	config.AddDefaultValue(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, func(_ configuration.Configuration, existingValue any) (any, error) {
		if existingValue == nil {
			return true, nil
		} else {
			return existingValue, nil
		}
	})

	err = config.AddKeyDependency(configuration.IS_FEDRAMP, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for IS_FEDRAMP:", err)
	}

	config.AddDefaultValue(configuration.IS_FEDRAMP, func(_ configuration.Configuration, existingValue any) (any, error) {
		if existingValue == nil {
			return api.IsFedramp(config.GetString(configuration.API_URL)), nil
		} else {
			return existingValue, nil
		}
	})

	config.AddDefaultValue(configuration.INPUT_DIRECTORY, defaultInputDirectory())
	config.AddDefaultValue(configuration.PREVIEW_FEATURES_ENABLED, defaultPreviewFeaturesEnabled(engine))
	config.AddDefaultValue(configuration.CUSTOM_CONFIG_FILES, customConfigFiles(config))
	config.AddDefaultValue(middleware.ConfigurationKeyRetryAttempts, defaultMaxNetworkRetryAttempts(engine))
	config.AddDefaultValue(configuration.FIPS_ENABLED, configuration.StandardDefaultValueFunction(fips140.Enabled()))
}

func customConfigFiles(config configuration.Configuration) configuration.DefaultValueFunction {
	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		var files []string
		// last file usually wins if the same values are configured
		// Precedence should be:
		//   1. std files in current folder
		//   2. given global config file
		//   3. std files global

		files = append(files, ".snyk.env")
		files = append(files, ".envrc")
		files = append(files, ".snyk.env."+runtime.GOOS)
		files = append(files, ".envrc."+runtime.GOOS)

		configFile := config.GetString("configfile")
		if configFile != "" {
			files = append(files, configFile)
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return files, err
		}

		files = append(files, filepath.Join(home, "/.snyk.env"))
		return files, nil
	}
}

// CreateAppEngine creates a new workflow engine.
func CreateAppEngine() workflow.Engine {
	discardLogger := log.New(io.Discard, "", 0)
	return CreateAppEngineWithOptions(WithConfiguration(configuration.New()), WithLogger(discardLogger))
}

func CreateAppEngineWithOptions(opts ...Opts) workflow.Engine {
	engine := workflow.NewDefaultWorkFlowEngine()

	for _, opt := range opts {
		opt(engine)
	}

	config := engine.GetConfiguration()
	if config != nil {
		initConfiguration(engine, config, engine.GetLogger(), nil)
	}

	engine.AddExtensionInitializer(localworkflows.Init)
	return engine
}

// Deprecated: Use CreateAppEngineWithOptions instead.
func CreateAppEngineWithLogger(logger *log.Logger) workflow.Engine {
	return CreateAppEngineWithOptions(WithLogger(logger))
}
