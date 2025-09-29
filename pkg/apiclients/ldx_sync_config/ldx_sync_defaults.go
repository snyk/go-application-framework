package ldx_sync_config

import (
	"net/http"

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
		inputDir := config.GetString(configuration.INPUT_DIRECTORY)
		return ResolveOrganization(config, engine, logger, inputDir, existingValue)
	}
}
