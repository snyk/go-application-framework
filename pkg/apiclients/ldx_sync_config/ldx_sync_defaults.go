package ldx_sync_config

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// LDX-Sync constants
const (
	LDX_SYNC_CONFIG = "internal_ldx_sync_config"
)

// createLdxSyncConfigClient creates a ClientWithResponsesInterface instance
func createLdxSyncConfigClient(url string, client *http.Client) (v20241015.ClientWithResponsesInterface, error) {
	ldxClient, err := v20241015.NewClientWithResponses(url, v20241015.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return ldxClient, nil
}

// DefaultFuncLdxSyncConfig provides a default function for retrieving LDX-Sync configuration
func DefaultFuncLdxSyncConfig(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(LDX_SYNC_CONFIG, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for "+LDX_SYNC_CONFIG+":", err)
	}

	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		ldxClient, err := createLdxSyncConfigClient(url, client)
		if err != nil {
			return nil, err
		}

		// If there's already a cached value, return it
		if existingValue != nil {
			return existingValue, nil
		}

		// Try to get LDX-Sync config based on current directory
		ldxConfig, err := GetConfig(config, ldxClient, logger)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to retrieve LDX-Sync config")
			return nil, err
		}

		logger.Debug().Msg("Successfully retrieved LDX-Sync config")
		return ldxConfig, nil
	}
}

// DefaultFuncOrganizationLdx provides LDX-Sync enhanced organization resolution
func DefaultFuncOrganizationLdx(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(configuration.ORGANIZATION, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for "+configuration.ORGANIZATION+":", err)
	}

	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		ldxClient, err := createLdxSyncConfigClient(url, client)
		if err != nil {
			return nil, err
		}

		// Handle existing organization value
		if orgId := handleExistingOrganization(existingValue, apiClient, logger); orgId != "" {
			return orgId, nil
		}

		// Try LDX-Sync resolution
		if orgId := TryResolveOrganization(config, ldxClient, logger); orgId != "" {
			return orgId, nil
		}

		// Fallback to default org resolution
		return getDefaultOrganization(apiClient, logger)
	}
}

// handleExistingOrganization validates and resolves existing organization values
func handleExistingOrganization(existingValue interface{}, apiClient api.ApiClient, logger *zerolog.Logger) string {
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

// getDefaultOrganization retrieves the default organization from the API
func getDefaultOrganization(apiClient api.ApiClient, logger *zerolog.Logger) (string, error) {
	orgId, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
	}
	return orgId, err
}
