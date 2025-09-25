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
func getLdxSyncConfig(config configuration.Configuration, ldxClient v20241015.ClientWithResponsesInterface, orgId string) LdxSyncConfigResult {
	inputDir := config.GetString(configuration.INPUT_DIRECTORY)
	if inputDir == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")}
	}

	remoteUrl, err := git.GetRemoteUrl(inputDir)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("git remote detection failed: %w", err)}
	}

	params := &v20241015.GetConfigParams{
		Version:   "2024-10-15",
		RemoteUrl: &remoteUrl,
		Org:       &orgId,
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

// TryResolveOrganization attempts to resolve organization using LDX-Sync or returns the default organization
func TryResolveOrganization(config configuration.Configuration, ldxClient v20241015.ClientWithResponsesInterface, logger *zerolog.Logger) string {
	cfgResult := getLdxSyncConfig(config, ldxClient, "")
	if cfgResult.Error != nil {
		logger.Debug().Err(cfgResult.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return ""
	}

	orgId := ""
	defaultOrgId := ""
	folderConfigs := cfgResult.Config.Data.Attributes.ConfigData.FolderConfigs

	if folderConfigs == nil || len(*folderConfigs) == 0 {
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("No folder configurations found in LDX-Sync config, so can't extract organization")
		return ""
	}

	// taking first folder config, because currently repo can have only 1 folderconfig
	for _, org := range *(*folderConfigs)[0].Organizations {
		if org.IsDefault != nil && *org.IsDefault {
			defaultOrgId = org.Id
		}
		if org.PreferredByAlgorithm != nil && *org.PreferredByAlgorithm {
			orgId = org.Id
			break
		}
	}

	if orgId == "" {
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("Failed to find organization with PreferredByAlgorithm = true, falling back to user default organization")
		if defaultOrgId == "" {
			logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("No default organization found in LDX-Sync config")
			return ""
		}
		return defaultOrgId
	}

	logger.Debug().Str("orgId", orgId).Str("remoteUrl", cfgResult.RemoteUrl).Str("projectRoot", cfgResult.ProjectRoot).Msg("Resolved organization via LDX-Sync")
	return orgId
}

func GetConfig(config configuration.Configuration, orgId string, ldxClient v20241015.ClientWithResponsesInterface, logger *zerolog.Logger) (*v20241015.ConfigResponse, error) {
	result := getLdxSyncConfig(config, ldxClient, orgId)
	if result.Error != nil {
		return nil, result.Error
	}
	return result.Config, nil
}
