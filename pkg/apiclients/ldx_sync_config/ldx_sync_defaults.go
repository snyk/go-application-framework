package ldx_sync_config

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// LDX-Sync constants
const (
	LDX_SYNC_CONFIG = "internal_ldx_sync_config"
)

// createLdxSyncConfigClient creates an LdxSyncConfigClient instance
func createLdxSyncConfigClient(url string, client *http.Client) LdxSyncConfigClient {
	ldxClient, err := NewLdxSyncConfigClient(url, WithCustomHTTPClient(client))
	if err != nil {
		// Return a no-op client that will fail gracefully
		return &noOpLdxSyncConfigClient{err: err}
	}
	return ldxClient
}

// noOpLdxSyncConfigClient is a no-op implementation that returns errors
type noOpLdxSyncConfigClient struct {
	err error
}

func (c *noOpLdxSyncConfigClient) GetConfiguration(ctx context.Context, params GetConfigurationParams) (*Configuration, error) {
	return nil, c.err
}

// createDefaultFunctionWithLdxClient creates a common pattern for default functions that need LDX-Sync client access
func createDefaultFunctionWithLdxClient(
	engine workflow.Engine,
	config configuration.Configuration,
	key string,
	logger *zerolog.Logger,
	ldxClientFactory func(url string, client *http.Client) LdxSyncConfigClient,
	callback func(config configuration.Configuration, existingValue interface{}, ldxClient LdxSyncConfigClient) (interface{}, error),
) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(key, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for "+key+":", err)
	}

	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		ldxClient := ldxClientFactory(url, client)
		return callback(config, existingValue, ldxClient)
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

// createDefaultFunctionWithHybridClient creates a common pattern for default functions that need both API and LDX-Sync client access
func createDefaultFunctionWithHybridClient(
	engine workflow.Engine,
	config configuration.Configuration,
	key string,
	logger *zerolog.Logger,
	apiClientFactory func(url string, client *http.Client) api.ApiClient,
	ldxClientFactory func(url string, client *http.Client) LdxSyncConfigClient,
	callback func(config configuration.Configuration, existingValue interface{}, apiClient api.ApiClient, ldxClient LdxSyncConfigClient) (interface{}, error),
) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(key, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for "+key+":", err)
	}

	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		ldxClient := ldxClientFactory(url, client)
		return callback(config, existingValue, apiClient, ldxClient)
	}
}

// DefaultFuncOrganizationLdx provides LDX-Sync enhanced organization resolution
func DefaultFuncOrganizationLdx(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	return createDefaultFunctionWithHybridClient(engine, config, configuration.ORGANIZATION, logger, apiClientFactory, createLdxSyncConfigClient, func(_ configuration.Configuration, existingValue interface{}, apiClient api.ApiClient, ldxClient LdxSyncConfigClient) (interface{}, error) {
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
	})
}

// DefaultFuncLdxSyncConfig provides a default function for retrieving LDX-Sync configuration
func DefaultFuncLdxSyncConfig(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	return createDefaultFunctionWithLdxClient(engine, config, LDX_SYNC_CONFIG, logger, createLdxSyncConfigClient, func(_ configuration.Configuration, existingValue interface{}, ldxClient LdxSyncConfigClient) (interface{}, error) {
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
	})
}
