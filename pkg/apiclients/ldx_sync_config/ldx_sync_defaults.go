package ldx_sync_config

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// DefaultFuncOrganizationLdx provides LDX-Sync enhanced organization resolution
func DefaultFuncOrganizationLdx(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger, apiClientFactory func(url string, client *http.Client) api.ApiClient) configuration.DefaultValueFunction {
	err := config.AddKeyDependency(configuration.ORGANIZATION, configuration.API_URL)
	if err != nil {
		logger.Print("Failed to add dependency for "+configuration.ORGANIZATION+":", err)
	}

	return func(_ configuration.Configuration, existingValue any) (any, error) {
		// Handle existing organization value
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := apiClientFactory(url, client)
		if orgId := handleExistingOrganization(existingValue, apiClient, logger); orgId != "" {
			return orgId, nil
		}

		// Try LDX-Sync resolution
		inputDir := config.GetString(configuration.INPUT_DIRECTORY)
		if orgId := ResolveOrganization(config, engine, logger, inputDir); orgId != "" {
			return orgId, nil
		}

		// Fallback to default org resolution
		orgId, err := apiClient.GetDefaultOrgId()
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		}
		return orgId, err
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
