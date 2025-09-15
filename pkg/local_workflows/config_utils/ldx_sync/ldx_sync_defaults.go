package ldx_sync

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// LDX-Sync constants
const (
	FF_LDX_SYNC_ORG_RESOLUTION = "internal_snyk_ldx_sync_org_resolution_enabled"
	LDX_SYNC_CONFIG            = "internal_ldx_sync_config"
)

// CreateDefaultFunctionWithApiClient creates a common pattern for default functions that need API client access
func CreateDefaultFunctionWithApiClient(
	engine workflow.Engine,
	config configuration.Configuration,
	key string,
	logger *zerolog.Logger,
	apiClientFactory func(url string, client *http.Client) api.ApiClient,
	callback func(config configuration.Configuration, existingValue interface{}, apiClient api.ApiClient) (interface{}, error),
) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(key, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for "+key+":", err)
	}

	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		return callback(config, existingValue, apiClient)
	}
}

// HandleExistingOrganization validates and resolves existing organization values
func HandleExistingOrganization(existingValue interface{}, apiClient api.ApiClient, logger *zerolog.Logger) string {
	existingString, ok := existingValue.(string)
	if existingValue == nil || !ok || len(existingString) == 0 {
		return ""
	}

	orgId := existingString
	_, err := uuid.Parse(orgId)
	isSlugName := err != nil

	if isSlugName {
		orgId, err = apiClient.GetOrgIdFromSlug(existingString)
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
			return ""
		}
	}

	return orgId
}

// GetDefaultOrganization retrieves the default organization from the API
func GetDefaultOrganization(apiClient api.ApiClient, logger *zerolog.Logger) (string, error) {
	orgId, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
	}
	return orgId, err
}

// DefaultFuncOrganizationLdx provides LDX-Sync enhanced organization resolution
func DefaultFuncOrganizationLdx(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	return CreateDefaultFunctionWithApiClient(engine, config, configuration.ORGANIZATION, logger, apiClientFactory, func(_ configuration.Configuration, existingValue interface{}, apiClient api.ApiClient) (interface{}, error) {
		// Handle existing organization value
		if orgId := HandleExistingOrganization(existingValue, apiClient, logger); orgId != "" {
			return orgId, nil
		}

		// Try LDX-Sync resolution
		if orgId := TryResolveOrganization(config, apiClient, logger); orgId != "" {
			return orgId, nil
		}

		// Fallback to default org resolution
		return GetDefaultOrganization(apiClient, logger)
	})
}

// DefaultFuncOrganization provides organization resolution with LDX-Sync feature flag
func DefaultFuncOrganization(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	// Check if LDX-Sync organization resolution is enabled
	if config.GetBool(FF_LDX_SYNC_ORG_RESOLUTION) {
		logger.Debug().Msg("LDX-Sync organization resolution enabled, using enhanced resolution")
		return DefaultFuncOrganizationLdx(engine, config, logger, apiClientFactory)
	}

	// Use original organization resolution logic
	logger.Debug().Msg("Using original organization resolution")
	return CreateDefaultFunctionWithApiClient(engine, config, configuration.ORGANIZATION, logger, apiClientFactory, func(_ configuration.Configuration, existingValue interface{}, apiClient api.ApiClient) (interface{}, error) {
		// Handle existing organization value
		if orgId := HandleExistingOrganization(existingValue, apiClient, logger); orgId != "" {
			return orgId, nil
		}

		// Fallback to default org resolution (original behavior)
		return GetDefaultOrganization(apiClient, logger)
	})
}

// DefaultFuncLdxSyncConfig provides a default function for retrieving LDX-Sync configuration
func DefaultFuncLdxSyncConfig(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	return CreateDefaultFunctionWithApiClient(engine, config, LDX_SYNC_CONFIG, logger, apiClientFactory, func(_ configuration.Configuration, existingValue interface{}, apiClient api.ApiClient) (interface{}, error) {
		// If there's already a cached value, return it
		if existingValue != nil {
			return existingValue, nil
		}

		// Try to get LDX-Sync config based on current directory
		ldxConfig, err := GetConfig(config, apiClient, logger)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to retrieve LDX-Sync config")
			return nil, err
		}

		logger.Debug().Msg("Successfully retrieved LDX-Sync config")
		return ldxConfig, nil
	})
}
