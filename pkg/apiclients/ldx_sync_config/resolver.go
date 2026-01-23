package ldx_sync_config

import (
	"context"
	"fmt"
	url2 "net/url"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/go-application-framework/internal/api"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// LdxSyncConfigResult contains the result of LDX-Sync config retrieval
type LdxSyncConfigResult struct {
	Config      *v20241015.UserConfigResponse
	RemoteUrl   string
	ProjectRoot string
	Error       error
}

// Organization is the struct we return to consumers. We redefine it so that consumers don't need to be aware of the
// LDX-Sync api version.
// For the initial release pf LDX-Sync they are identical so we use an alias.
type Organization v20241015.Organization

// newClient is a variable that holds the function to create a new LDX-Sync client.
// It can be replaced in tests to inject a mock client.
var (
	newClient    = newClientImpl
	newApiClient = newApiClientImpl
)

func newClientImpl(engine workflow.Engine, config configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
	client := engine.GetNetworkAccess().GetHttpClient()
	url, err := url2.JoinPath(config.GetString(configuration.API_URL), "rest")
	if err != nil {
		return nil, err
	}
	return v20241015.NewClientWithResponses(url, v20241015.WithHTTPClient(client))
}

func newApiClientImpl(engine workflow.Engine, config configuration.Configuration) api.ApiClient {
	client := engine.GetNetworkAccess().GetHttpClient()
	url := config.GetString(configuration.API_URL)
	return api.NewApi(url, client)
}

// TODO remove
func ResolveOrganization(config configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger, dir string, existingOrgID string) (Organization, error) {
	return Organization{}, nil
}

// resolveOrgIdToUUID resolves a non-empty organization ID (UUID or slug) to a UUID
func resolveOrgIdToUUID(orgId string, engine workflow.Engine, config configuration.Configuration) (*uuid.UUID, error) {
	// Try to parse as UUID first to determine if it's a slug
	parsedUUID, err := uuid.Parse(orgId)
	if err == nil {
		// Already a valid UUID
		return &parsedUUID, nil
	}

	// Not a UUID, try to resolve as slug
	apiClient := newApiClient(engine, config)
	resolvedOrgId, err := apiClient.GetOrgIdFromSlug(orgId)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve organization slug: %w", err)
	}

	parsedUUID, err = uuid.Parse(resolvedOrgId)
	if err != nil {
		return nil, fmt.Errorf("invalid organization ID: %w", err)
	}

	return &parsedUUID, nil
}

// GetUserConfigForProject retrieves LDX-Sync user configuration for the current project
func GetUserConfigForProject(engine workflow.Engine, dir string, orgId string) LdxSyncConfigResult {
	if dir == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")}
	}

	config := engine.GetConfiguration()
	ldxClient, err := newClient(engine, config)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("failed to create LDX-Sync client: %w", err)}
	}

	remoteUrl, err := git.GetRemoteUrl(dir)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("git remote detection failed: %w", err)}
	}

	merged := true
	params := &v20241015.GetUserConfigParams{
		Version: "2024-10-15",
		Merged:  &merged,
	}

	if remoteUrl != "" {
		params.RemoteUrl = &remoteUrl
	}

	if orgId != "" {
		var orgUUID *uuid.UUID
		orgUUID, err = resolveOrgIdToUUID(orgId, engine, config)
		if err != nil {
			return LdxSyncConfigResult{Error: err}
		}
		params.Org = orgUUID
	}

	response, err := ldxClient.GetUserConfigWithResponse(context.Background(), params)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("failed to retrieve LDX-Sync config: %w", err)}
	}

	// Check for errors in the response
	if response.JSON400 != nil || response.JSON401 != nil || response.JSON404 != nil || response.JSON500 != nil || response.JSON501 != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("%d API error occurred", response.HTTPResponse.StatusCode)}
	}

	var configResponse *v20241015.UserConfigResponse
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

// ResolveOrgFromUserConfig attempts to resolve an organization from user config.
// It follows this order:
// 1. Tries to find a preferred organization from LDX-Sync configuration.
// 2. Falls back to the user's default organization from LDX-Sync.
// 3. Falls back to the user's default organization from the Snyk API.
func ResolveOrgFromUserConfig(engine workflow.Engine, cfgResult LdxSyncConfigResult) (Organization, error) {
	config := engine.GetConfiguration()
	logger := engine.GetLogger()

	// Create apiClient once for all operations that need it
	apiClient := newApiClient(engine, config)

	// 1. Try LDX-Sync resolution
	if cfgResult.Error != nil {
		logger.Debug().Err(cfgResult.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return fallbackOrganization(nil, apiClient, "", logger)
	}

	// Try to find preferred organization from organizations list
	if cfgResult.Config.Data.Attributes.Organizations != nil {
		for _, org := range *cfgResult.Config.Data.Attributes.Organizations {
			if org.PreferredByAlgorithm != nil && *org.PreferredByAlgorithm {
				logger.Debug().Str("orgId", org.Id).Str("remoteUrl", cfgResult.RemoteUrl).Str("projectRoot", cfgResult.ProjectRoot).Msg("Resolved organization via LDX-Sync")
				return Organization(org), nil
			}
		}
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("Failed to find organization with PreferredByAlgorithm = true, falling back to user default organization")
	} else {
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("No organizations found in LDX-Sync config, falling back to user default organization")
	}

	// 2 & 3. Fallback
	return fallbackOrganization(cfgResult.Config.Data.Attributes.Organizations, apiClient, cfgResult.RemoteUrl, logger)
}

func getDefaultOrganization(apiClient api.ApiClient, logger *zerolog.Logger) (Organization, error) {
	defaultOrgId, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		return Organization{}, err
	}

	return Organization{Id: defaultOrgId, IsDefault: utils.Ptr(true)}, nil
}

func fallbackOrganization(organizations *[]v20241015.Organization, apiClient api.ApiClient, remoteUrl string, logger *zerolog.Logger) (Organization, error) {
	// Fallback to default user organization from LDX-Sync response
	if organizations != nil {
		for _, org := range *organizations {
			if org.IsDefault != nil && *org.IsDefault {
				logger.Debug().Str("orgId", org.Id).Str("remoteUrl", remoteUrl).Msg("Resolved organization via LDX-Sync fallback (user default)")
				return Organization(org), nil
			}
		}
		logger.Debug().Str("remoteUrl", remoteUrl).Msg("No default organization found in LDX-Sync config, falling back to API default")
	}

	// Fallback to default org resolution from API
	return getDefaultOrganization(apiClient, logger)
}
