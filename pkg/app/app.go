package app

import (
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
	pkg_utils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func defaultFuncOrganizationSlug(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		orgId := config.GetString(configuration.ORGANIZATION)
		if len(orgId) == 0 {
			return existingValue
		}
		slugName, err := apiClient.GetSlugFromOrgId(orgId)
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION_SLUG\":", err)
		}
		return slugName
	}
	return callback
}

func defaultFuncOrganization(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
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
					return orgId
				}
			} else {
				return orgId
			}
		}

		orgId, err := apiClient.GetDefaultOrgId()
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		}

		return orgId
	}
	return callback
}

func defaultFuncApiUrl(config configuration.Configuration, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		urlString := constants.SNYK_DEFAULT_API_URL

		// configured value takes precedence
		if existingValue != nil {
			if temp, ok := existingValue.(string); ok {
				urlString = temp
			}
		} else { // extract API URL from token
			urlFromOauthToken, err := auth.GetAudienceClaimFromOauthToken(config)
			if err != nil {
				logger.Warn().Err(err).Msg("failed to read oauth token")
			}

			if len(urlFromOauthToken) > 0 && len(urlFromOauthToken[0]) > 0 {
				urlString = urlFromOauthToken[0]
			}
		}

		apiString, err := api.GetCanonicalApiUrlFromString(urlString)
		if err != nil {
			logger.Warn().Err(err).Str(configuration.API_URL, urlString).Msg("failed to get api url")
		}
		return apiString
	}
	return callback
}

func defaultInputDirectory() configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		if existingValue == nil {
			path, err := os.Getwd()
			if err != nil {
				return ""
			}
			return path
		} else {
			return existingValue
		}
	}
	return callback
}

func defaultTempDirectory(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
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

			return existingValue
		}

		tmpDir := pkg_utils.GetTemporaryDirectory(config.GetString(configuration.CACHE_PATH), version)
		err := pkg_utils.CreateAllDirectories(tmpDir, version)
		if err != nil {
			logger.Err(err)
		}

		return tmpDir
	}
	return callback
}

func defaultPreviewFeaturesEnabled(engine workflow.Engine, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		if existingValue != nil {
			return existingValue
		}

		ri := engine.GetRuntimeInfo()
		if ri == nil {
			return false
		}

		version := ri.GetVersion()

		if strings.Contains(version, "-preview") || strings.Contains(version, "-dev") {
			logger.Warn().Msg("Using a preview feature!")
			return true
		}

		return false
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
	config.AddDefaultValue(auth.CONFIG_KEY_ALLOWED_HOST_REGEXP, configuration.StandardDefaultValueFunction(`^api(\.(.+))?\.snyk|snykgov\.io$`))

	// set default filesize threshold to 512MB
	config.AddDefaultValue(configuration.IN_MEMORY_THRESHOLD_BYTES, configuration.StandardDefaultValueFunction(constants.SNYK_DEFAULT_IN_MEMORY_THRESHOLD_MB))
	config.AddDefaultValue(configuration.API_URL, defaultFuncApiUrl(config, logger))
	config.AddDefaultValue(configuration.TEMP_DIR_PATH, defaultTempDirectory(engine, config, logger))

	config.AddDefaultValue(configuration.WEB_APP_URL, func(existingValue any) any {
		canonicalApiUrl := config.GetString(configuration.API_URL)
		appUrl, err := api.DeriveAppUrl(canonicalApiUrl)
		if err != nil {
			logger.Print("Failed to determine default value for \"WEB_APP_URL\":", err)
		}

		return appUrl
	})

	config.AddDefaultValue(configuration.ORGANIZATION, defaultFuncOrganization(engine, config, logger, apiClientFactory))
	config.AddDefaultValue(configuration.ORGANIZATION_SLUG, defaultFuncOrganizationSlug(engine, config, logger, apiClientFactory))

	config.AddDefaultValue(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, func(existingValue any) any {
		if existingValue == nil {
			return true
		} else {
			return existingValue
		}
	})

	config.AddDefaultValue(configuration.IS_FEDRAMP, func(existingValue any) any {
		if existingValue == nil {
			return api.IsFedramp(config.GetString(configuration.API_URL))
		} else {
			return existingValue
		}
	})

	config.AddDefaultValue(configuration.INPUT_DIRECTORY, defaultInputDirectory())
	config.AddDefaultValue(configuration.PREVIEW_FEATURES_ENABLED, defaultPreviewFeaturesEnabled(engine, logger))
	config.AddDefaultValue(configuration.CUSTOM_CONFIG_FILES, customConfigFiles(config))
}

func customConfigFiles(config configuration.Configuration) configuration.DefaultValueFunction {
	return func(existingValue interface{}) interface{} {
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
			return files
		}

		files = append(files, filepath.Join(home, "/.snyk.env"))
		return files
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
