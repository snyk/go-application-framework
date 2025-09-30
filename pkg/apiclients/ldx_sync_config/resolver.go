package ldx_sync_config

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// LdxSyncConfigResult contains the result of LDX-Sync config retrieval
type LdxSyncConfigResult struct {
	Config      *v20241015.ConfigResponse
	RemoteUrl   string
	ProjectRoot string
	Error       error
}

// newClient is a variable that holds the function to create a new LDX-Sync client.
// It can be replaced in tests to inject a mock client.
var (
	newClient    = newClientImpl
	newApiClient = newApiClientImpl
)

func newClientImpl(engine workflow.Engine, config configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
	client := engine.GetNetworkAccess().GetHttpClient()
	url := config.GetString(configuration.API_URL)
	return v20241015.NewClientWithResponses(url, v20241015.WithHTTPClient(client))
}

func newApiClientImpl(engine workflow.Engine, config configuration.Configuration) api.ApiClient {
	client := engine.GetNetworkAccess().GetHttpClient()
	url := config.GetString(configuration.API_URL)
	return api.NewApi(url, client)
}

// getLdxSyncConfig retrieves LDX-Sync configuration for the current project
func getLdxSyncConfig(ldxClient v20241015.ClientWithResponsesInterface, orgId string, dir string) LdxSyncConfigResult {
	if dir == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")}
	}

	remoteUrl, err := git.GetRemoteUrl(dir)
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
		return LdxSyncConfigResult{Error: fmt.Errorf("%d API error occurred", response.HTTPResponse.StatusCode)}
	}

	var configResponse *v20241015.ConfigResponse
	if response.JSON200 != nil {
		configResponse = response.JSON200
	} else if response.ApplicationvndApiJSON200 != nil {
		configResponse = response.ApplicationvndApiJSON200
	} else {
		return LdxSyncConfigResult{Error: fmt.Errorf("no configuration data in response, status code: %d", response.HTTPResponse.StatusCode)}
	}

	return LdxSyncConfigResult{
		Config:      configResponse,
		RemoteUrl:   remoteUrl,
		ProjectRoot: dir,
		Error:       nil,
	}
}

// ResolveOrganization attempts to resolve an organization.
// It follows this order:
// 1. Validates and resolves the existing organization value if provided.
// 2. Tries to find a preferred organization from LDX-Sync folder configurations.
// 3. Falls back to the user's default organization from LDX-Sync.
// 4. Falls back to the user's default organization from the Snyk API.
func ResolveOrganization(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, dir string, existingOrgValue any) (string, error) {
	apiClient := newApiClient(engine, config)
	// 1. Handle existing organization value
	if orgId, err := handleExistingOrganization(existingOrgValue, apiClient, logger); orgId != "" || err != nil {
		return orgId, err
	}

	// 2. Try LDX-Sync resolution
	ldxClient, err := newClient(engine, config)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to create LDX-Sync client, can't proceed with LDX-Sync resolution")
		return fallbackOrganization(nil, apiClient, "", logger)
	}

	cfgResult := getLdxSyncConfig(ldxClient, "", dir)
	if cfgResult.Error != nil {
		logger.Debug().Err(cfgResult.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return fallbackOrganization(nil, apiClient, "", logger)
	}

	configData := cfgResult.Config.Data.Attributes.ConfigData

	// Try to find preferred organization from folder configs
	if configData.FolderConfigs != nil && len(*configData.FolderConfigs) > 0 {
		// taking first folder config, because currently repo can have only 1 folderconfig
		firstFolderConfig := (*configData.FolderConfigs)[0]
		if firstFolderConfig.Organizations != nil {
			for _, org := range *firstFolderConfig.Organizations {
				if org.PreferredByAlgorithm != nil && *org.PreferredByAlgorithm {
					logger.Debug().Str("orgId", org.Id).Str("remoteUrl", cfgResult.RemoteUrl).Str("projectRoot", cfgResult.ProjectRoot).Msg("Resolved organization via LDX-Sync")
					return org.Id, nil
				}
			}
		}
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("Failed to find organization with PreferredByAlgorithm = true, falling back to user default organization")
	} else {
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("No folder configurations found in LDX-Sync config, falling back to user default organization")
	}

	// 3 & 4. Fallback
	return fallbackOrganization(&configData, apiClient, cfgResult.RemoteUrl, logger)
}

func handleExistingOrganization(existingValue any, apiClient api.ApiClient, logger *zerolog.Logger) (string, error) {
	existingString, ok := existingValue.(string)
	if existingValue == nil || !ok || len(existingString) == 0 {
		logger.Debug().Msg("Existing organization value provided is not a string")
		return "", nil
	}

	orgId := existingString
	_, err := uuid.Parse(orgId)
	isSlugName := err != nil

	if isSlugName {
		orgId, err = apiClient.GetOrgIdFromSlug(existingString)
		if err != nil {
			logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
			return "", err
		}
	}

	defaultOrgId, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Print("Failed to determine default value, so can't compare to the existing value, for \"ORGANIZATION\":", err)
		return orgId, nil
	}

	// special case for migrating users from defaultOrg to ldx-sync based one
	if defaultOrgId == orgId {
		return "", nil
	}

	return orgId, nil
}

func fallbackOrganization(configData *v20241015.ConfigData, apiClient api.ApiClient, remoteUrl string, logger *zerolog.Logger) (string, error) {
	// Fallback to default user organization from LDX-Sync response
	if configData != nil && configData.Organizations != nil {
		for _, org := range *configData.Organizations {
			if org.IsDefault != nil && *org.IsDefault {
				logger.Debug().Str("orgId", org.Id).Str("remoteUrl", remoteUrl).Msg("Resolved organization via LDX-Sync fallback (user default)")
				return org.Id, nil
			}
		}
		logger.Debug().Str("remoteUrl", remoteUrl).Msg("No default organization found in LDX-Sync config, falling back to API default")
	}

	// Fallback to default org resolution from API
	orgId, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		return "", err
	}
	return orgId, nil
}
