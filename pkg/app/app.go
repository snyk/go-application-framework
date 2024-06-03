package app

import (
	"io"
	"log"
	"os"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/snyk/go-httpauth/pkg/httpauth"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func defaultFunc_FF_CODE_CONSISTENT_IGNORES(engine workflow.Engine, config configuration.Configuration, apiClient api.ApiClient, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		if existingValue == nil {
			flagname := "snykCodeConsistentIgnores"
			client := engine.GetNetworkAccess().GetHttpClient()
			url := config.GetString(configuration.API_URL)
			org := config.GetString(configuration.ORGANIZATION)
			apiClient.Init(url, client)
			result, err := apiClient.GetFeatureFlag(flagname, org)
			if err != nil {
				logger.Printf("Failed to determine feature flag \"%s\" for org \"%s\": %s", flagname, org, err)
			}
			return result
		} else {
			return existingValue
		}
	}
	return callback
}

func defaultFuncOrganizationSlug(engine workflow.Engine, config configuration.Configuration, apiClient api.ApiClient, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient.Init(url, client)
		orgId := config.GetString(configuration.ORGANIZATION)
		slugName, err := apiClient.GetSlugFromOrgId(orgId)
		if err != nil {
			logger.Print("Failed to determine default value for \"INTERNAL_ORGANIZATION_SLUG\":", err)
		}
		if len(slugName) == 0 {
			return existingValue
		}
		return slugName
	}
	return callback
}

func defaultFuncOrganization(engine workflow.Engine, config configuration.Configuration, apiClient api.ApiClient, logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient.Init(url, client)
		existingString, ok := existingValue.(string)
		if existingValue != nil && ok && len(existingString) > 0 {
			orgId := existingString
			_, err := uuid.Parse(orgId)
			isSlugName := err != nil
			if isSlugName {
				config.Set("INTERNAL_ORGANIZATION_SLUG", existingString)
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

		slugName, err := apiClient.GetSlugFromOrgId(orgId)
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		}
		config.Set("INTERNAL_ORGANIZATION_SLUG", slugName)

		return orgId
	}
	return callback
}

func defaultFuncApiUrl(logger *zerolog.Logger) configuration.DefaultValueFunction {
	callback := func(existingValue interface{}) interface{} {
		urlString := constants.SNYK_DEFAULT_API_URL

		if existingValue != nil {
			if temp, ok := existingValue.(string); ok {
				urlString = temp
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

// initConfiguration initializes the configuration with initial values.
func initConfiguration(engine workflow.Engine, config configuration.Configuration, apiClient api.ApiClient, logger *zerolog.Logger) {
	if logger == nil {
		logger = &zlog.Logger
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

	config.AddDefaultValue(configuration.API_URL, defaultFuncApiUrl(logger))

	config.AddDefaultValue(configuration.WEB_APP_URL, func(existingValue any) any {
		canonicalApiUrl := config.GetString(configuration.API_URL)
		appUrl, err := api.DeriveAppUrl(canonicalApiUrl)
		if err != nil {
			logger.Print("Failed to determine default value for \"WEB_APP_URL\":", err)
		}

		return appUrl
	})

	config.AddDefaultValue(configuration.ORGANIZATION, defaultFuncOrganization(engine, config, apiClient, logger))
	config.AddDefaultValue(configuration.INTERNAL_ORGANIZATION_SLUG, defaultFuncOrganizationSlug(engine, config, apiClient, logger))

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
	config.AddDefaultValue(configuration.FF_CODE_CONSISTENT_IGNORES, defaultFunc_FF_CODE_CONSISTENT_IGNORES(engine, config, apiClient, logger))
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
		initConfiguration(engine, config, api.NewApiInstance(), engine.GetLogger())
	}

	engine.AddExtensionInitializer(localworkflows.Init)
	return engine
}

// Deprecated: Use CreateAppEngineWithOptions instead.
func CreateAppEngineWithLogger(logger *log.Logger) workflow.Engine {
	return CreateAppEngineWithOptions(WithLogger(logger))
}
