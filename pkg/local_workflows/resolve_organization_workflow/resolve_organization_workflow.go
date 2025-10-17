package resolve_organization_workflow

import (
	"context"
	"fmt"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/api"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	resolveOrganizationWorkflowName = "resolve.organization"
)

// WORKFLOWID_RESOLVE_ORGANIZATION is the workflow identifier for the resolve organization workflow
var WORKFLOWID_RESOLVE_ORGANIZATION workflow.Identifier = workflow.NewWorkflowIdentifier(resolveOrganizationWorkflowName)

// LdxSyncConfigResult contains the result of LDX-Sync config retrieval
type LdxSyncConfigResult struct {
	Config      *v20241015.ConfigResponse
	RemoteUrl   string
	ProjectRoot string
	Error       error
}

// Organization is the struct we return to consumers. We redefine it so that consumers don't need to be aware of the
// LDX-Sync api version.
// For the initial release of LDX-Sync they are identical so we use an alias.
type Organization v20241015.Organization

// ResolveOrganizationInput is the input for the resolve organization workflow
type ResolveOrganizationInput struct {
	Directory string `json:"directory"`
}

// ResolveOrganizationOutput is the output for the resolve organization workflow
type ResolveOrganizationOutput struct {
	Organization Organization `json:"organization"`
}

// InitResolveOrganizationWorkflow initializes the resolve organization workflow
func InitResolveOrganizationWorkflow(engine workflow.Engine) error {
	flagset := pflag.NewFlagSet(resolveOrganizationWorkflowName, pflag.ContinueOnError)
	_, err := engine.Register(WORKFLOWID_RESOLVE_ORGANIZATION, workflow.ConfigurationOptionsFromFlagset(flagset), resolveOrganizationWorkflowEntryPoint)
	return err
}

// resolveOrganizationWorkflowEntryPoint is the entry point for the resolve organization workflow
func resolveOrganizationWorkflowEntryPoint(invocationCtx workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
	engine := invocationCtx.GetEngine()
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	// Create LDX-Sync client (may be nil if creation fails)
	ldxClient, err := newLdxSyncClientImpl(engine, config)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to create LDX-Sync client, will fall back to API default organization")
		ldxClient = nil
	}

	// Create API client
	apiClient := newApiClientImpl(engine, config)

	// Call DI version with dependencies
	return resolveOrganizationWorkflowEntryPointDI(invocationCtx, input, ldxClient, apiClient)
}

// resolveOrganizationWorkflowEntryPointDI is the testable entry point with dependency injection
func resolveOrganizationWorkflowEntryPointDI(
	invocationCtx workflow.InvocationContext,
	input []workflow.Data,
	ldxClient v20241015.ClientWithResponsesInterface,
	apiClient api.ApiClient,
) ([]workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()

	// Parse input
	if len(input) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

	resolveInput, ok := input[0].GetPayload().(ResolveOrganizationInput)
	if !ok {
		return nil, fmt.Errorf("invalid input payload type: expected ResolveOrganizationInput")
	}

	// Validate input
	if resolveInput.Directory == "" {
		return nil, fmt.Errorf("directory is required")
	}

	// Resolve the organization
	org, err := resolveOrganizationInternal(logger, apiClient, ldxClient, resolveInput.Directory)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve organization: %w", err)
	}

	// Create output
	output := ResolveOrganizationOutput{
		Organization: org,
	}

	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_RESOLVE_ORGANIZATION, "resolve-org-output"),
		"application/go-struct",
		output,
	)

	return []workflow.Data{outputData}, nil
}

// resolveOrganizationInternal contains the core organization resolution logic
// It follows this order:
// 1. Tries to find a preferred organization from LDX-Sync folder configurations.
// 2. Falls back to the user's default organization from LDX-Sync.
// 3. Falls back to the user's default organization from the Snyk API.
func resolveOrganizationInternal(logger *zerolog.Logger, apiClient api.ApiClient, ldxClient v20241015.ClientWithResponsesInterface, dir string) (Organization, error) {
	// 1. Try LDX-Sync resolution
	if ldxClient == nil {
		logger.Debug().Msg("LDX-Sync client not available, falling back to default")
		return fallbackOrganization(logger, apiClient, nil, "")
	}

	cfgResult := getLdxSyncConfig(ldxClient, "", dir)
	if cfgResult.Error != nil {
		logger.Debug().Err(cfgResult.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return fallbackOrganization(logger, apiClient, nil, "")
	}

	configData := cfgResult.Config.Data.Attributes.ConfigData

	// Try to find preferred organization from folder configs
	if configData.FolderConfigs != nil && len(*configData.FolderConfigs) > 0 {
		// taking first folder config, because currently repo can have only 1 folder config
		firstFolderConfig := (*configData.FolderConfigs)[0]
		if firstFolderConfig.Organizations != nil {
			for _, org := range *firstFolderConfig.Organizations {
				if org.PreferredByAlgorithm != nil && *org.PreferredByAlgorithm {
					logger.Debug().Str("orgId", org.Id).Str("remoteUrl", cfgResult.RemoteUrl).Str("projectRoot", cfgResult.ProjectRoot).Msg("Resolved organization via LDX-Sync")
					return Organization(org), nil
				}
			}
		}
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("Failed to find organization with PreferredByAlgorithm = true, falling back to user default organization")
	} else {
		logger.Debug().Str("remoteUrl", cfgResult.RemoteUrl).Msg("No folder configurations found in LDX-Sync config, falling back to user default organization")
	}

	// 2 & 3. Fallback
	return fallbackOrganization(logger, apiClient, &configData, cfgResult.RemoteUrl)
}

func getDefaultOrganization(logger *zerolog.Logger, apiClient api.ApiClient) (Organization, error) {
	defaultOrgId, err := apiClient.GetDefaultOrgId()
	if err != nil {
		logger.Print("Failed to determine default value for \"ORGANIZATION\":", err)
		return Organization{}, err
	}

	return Organization{Id: defaultOrgId, IsDefault: utils.Ptr(true)}, nil
}

func fallbackOrganization(logger *zerolog.Logger, apiClient api.ApiClient, configData *v20241015.ConfigData, remoteUrl string) (Organization, error) {
	// Fallback to default user organization from LDX-Sync response
	if configData != nil && configData.Organizations != nil {
		for _, org := range *configData.Organizations {
			if org.IsDefault != nil && *org.IsDefault {
				logger.Debug().Str("orgId", org.Id).Str("remoteUrl", remoteUrl).Msg("Resolved organization via LDX-Sync fallback (user default)")
				return Organization(org), nil
			}
		}
		logger.Debug().Str("remoteUrl", remoteUrl).Msg("No default organization found in LDX-Sync config, falling back to API default")
	}

	// Fallback to default org resolution from API
	return getDefaultOrganization(logger, apiClient)
}

func getLdxSyncConfig(ldxClient v20241015.ClientWithResponsesInterface, orgId string, dir string) LdxSyncConfigResult {
	if dir == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")}
	}

	remoteUrl, err := git.GetRemoteUrl(dir)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("git remote detection failed: %w", err)}
	}

	params := &v20241015.GetConfigParams{
		Version: "2024-10-15",
	}

	if orgId != "" {
		params.Org = &orgId
	}

	if remoteUrl != "" {
		params.RemoteUrl = &remoteUrl
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

func newLdxSyncClientImpl(engine workflow.Engine, config configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
	restURL, err := url.JoinPath(config.GetString(configuration.API_URL), "rest")
	if err != nil {
		return nil, err
	}
	client := engine.GetNetworkAccess().GetHttpClient()
	return v20241015.NewClientWithResponses(restURL, v20241015.WithHTTPClient(client))
}

func newApiClientImpl(engine workflow.Engine, config configuration.Configuration) api.ApiClient {
	apiURL := config.GetString(configuration.API_URL)
	client := engine.GetNetworkAccess().GetHttpClient()
	return api.NewApi(apiURL, client)
}
