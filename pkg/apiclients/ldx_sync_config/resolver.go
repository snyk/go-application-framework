package ldx_sync_config

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

// LdxSyncConfigResult contains the result of LDX-Sync config retrieval
type LdxSyncConfigResult struct {
	Config      *v20241015.ConfigResponse
	RemoteUrl   string
	ProjectRoot string
	Error       error
}

// getLdxSyncConfig retrieves LDX-Sync configuration for the current project
func getLdxSyncConfig(config configuration.Configuration, ldxClient v20241015.ClientWithResponsesInterface) LdxSyncConfigResult {
	inputDir := config.GetString(configuration.INPUT_DIRECTORY)
	if inputDir == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")}
	}

	remoteUrl, err := git.GetRemoteUrl(inputDir)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("git remote detection failed: %w", err)}
	}

	params := &v20241015.GetConfigParams{
		Version:   "2024-10-15", // Use the API version
		RemoteUrl: &remoteUrl,
	}

	response, err := ldxClient.GetConfigWithResponse(context.Background(), params)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("failed to retrieve LDX-Sync config: %w", err)}
	}

	// Check for errors in the response
	if response.JSON400 != nil || response.JSON401 != nil || response.JSON404 != nil || response.JSON500 != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("API error occurred")}
	}

	// Extract the configuration from the response
	var configResponse *v20241015.ConfigResponse
	if response.JSON200 != nil {
		configResponse = response.JSON200
	} else if response.ApplicationvndApiJSON200 != nil {
		configResponse = response.ApplicationvndApiJSON200
	} else {
		return LdxSyncConfigResult{Error: fmt.Errorf("no configuration data in response")}
	}

	return LdxSyncConfigResult{
		Config:      configResponse,
		RemoteUrl:   remoteUrl,
		ProjectRoot: inputDir,
		Error:       nil,
	}
}

// TryResolveOrganization attempts to resolve organization using LDX-Sync
func TryResolveOrganization(config configuration.Configuration, ldxClient v20241015.ClientWithResponsesInterface, logger *zerolog.Logger) string {
	result := getLdxSyncConfig(config, ldxClient)
	if result.Error != nil {
		logger.Debug().Err(result.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return ""
	}

	// Extract organization from the response
	orgId := ""
	if result.Config.Data.Attributes.ConfigData.Organizations != nil &&
		len(*result.Config.Data.Attributes.ConfigData.Organizations) > 0 {
		// Find the default organization or use the first one
		for _, org := range *result.Config.Data.Attributes.ConfigData.Organizations {
			if org.IsDefault != nil && *org.IsDefault {
				orgId = org.Id
				break
			}
		}
		if orgId == "" {
			orgId = (*result.Config.Data.Attributes.ConfigData.Organizations)[0].Id
		}
	}

	if orgId != "" {
		logger.Debug().Str("orgId", orgId).Str("remoteUrl", result.RemoteUrl).Str("projectRoot", result.ProjectRoot).Msg("Resolved organization via LDX-Sync")
		return orgId
	}

	logger.Debug().Str("remoteUrl", result.RemoteUrl).Msg("No matching organization found in LDX-Sync config, falling back to default")
	return ""
}

// GetConfig retrieves LDX-Sync configuration for the current project
func GetConfig(config configuration.Configuration, ldxClient v20241015.ClientWithResponsesInterface, logger *zerolog.Logger) (*v20241015.ConfigResponse, error) {
	result := getLdxSyncConfig(config, ldxClient)
	if result.Error != nil {
		return nil, result.Error
	}

	// Return the configuration response directly
	return result.Config, nil
}
