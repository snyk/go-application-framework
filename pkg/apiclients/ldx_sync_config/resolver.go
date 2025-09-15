package ldx_sync_config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
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
func getLdxSyncConfig(config configuration.Configuration, apiClient api.ApiClient) LdxSyncConfigResult {
	inputDir := config.GetString(configuration.INPUT_DIRECTORY)
	if inputDir == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")}
	}

	projectRoot := findProjectRoot(inputDir)
	if projectRoot == "" {
		return LdxSyncConfigResult{Error: fmt.Errorf("no git repository found in input directory: %s", inputDir)}
	}

	remoteUrl, err := git.GetRemoteUrl(projectRoot)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("git remote detection failed: %w", err)}
	}

	ldxConfig, err := apiClient.GetLdxSyncConfig(remoteUrl)
	if err != nil {
		return LdxSyncConfigResult{Error: fmt.Errorf("failed to retrieve LDX-Sync config: %w", err)}
	}

	return LdxSyncConfigResult{
		Config:      ldxConfig,
		RemoteUrl:   remoteUrl,
		ProjectRoot: projectRoot,
		Error:       nil,
	}
}

// TryResolveOrganization attempts to resolve organization using LDX-Sync
func TryResolveOrganization(config configuration.Configuration, apiClient api.ApiClient, logger *zerolog.Logger) string {
	result := getLdxSyncConfig(config, apiClient)
	if result.Error != nil {
		logger.Debug().Err(result.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return ""
	}

	// Try to find organization from folder configs first (more specific)
	orgId := findOrganizationFromFolderConfigs(result.Config, result.RemoteUrl)
	if orgId == "" {
		// Fall back to default organization from main organizations list
		orgId = findDefaultOrganization(result.Config)
	}

	if orgId != "" {
		logger.Debug().Str("orgId", orgId).Str("remoteUrl", result.RemoteUrl).Str("projectRoot", result.ProjectRoot).Msg("Resolved organization via LDX-Sync")
		return orgId
	}

	logger.Debug().Str("remoteUrl", result.RemoteUrl).Msg("No matching organization found in LDX-Sync config, falling back to default")
	return ""
}

// GetConfig retrieves LDX-Sync configuration for the current project
func GetConfig(config configuration.Configuration, apiClient api.ApiClient, logger *zerolog.Logger) (*Configuration, error) {
	result := getLdxSyncConfig(config, apiClient)
	if result.Error != nil {
		return nil, result.Error
	}

	// Convert the raw ConfigResponse to our high-level Configuration struct
	configuration := convertToHighLevelConfig(result.Config)
	return configuration, nil
}

// convertToHighLevelConfig converts a raw ConfigResponse to our high-level Configuration struct
func convertToHighLevelConfig(configResponse *v20241015.ConfigResponse) *Configuration {
	config := &Configuration{}
	configData := &configResponse.Data.Attributes.ConfigData

	// Extract core configuration
	extractCoreConfig(configData, config)
	extractIdeConfig(configData, config)
	extractProxyConfig(configData, config)

	return config
}

// extractCoreConfig extracts core configuration fields
func extractCoreConfig(configData *v20241015.ConfigData, config *Configuration) {
	// Extract organization
	if configData.Organizations != nil && len(*configData.Organizations) > 0 {
		selectedOrg := findDefaultOrganizationFromList(*configData.Organizations)
		if selectedOrg != nil {
			config.Organization = selectedOrg.Id
		}
	}

	// Extract filter configuration
	if configData.FilterConfig != nil && configData.FilterConfig.Severities != nil {
		severities := configData.FilterConfig.Severities
		config.SeverityFilter = &SeverityFilter{
			Critical: *severities.Critical,
			High:     *severities.High,
			Medium:   *severities.Medium,
			Low:      *severities.Low,
		}
	}
}

// extractIdeConfig extracts IDE configuration
func extractIdeConfig(configData *v20241015.ConfigData, config *Configuration) {
	if configData.IdeConfig == nil {
		return
	}

	ideConfig := configData.IdeConfig

	// Extract product configuration
	if ideConfig.ProductConfig != nil {
		productConfig := ideConfig.ProductConfig
		config.ProductConfig = &ProductConfig{
			Code:      productConfig.Code != nil && *productConfig.Code,
			Container: productConfig.Container != nil && *productConfig.Container,
			Iac:       productConfig.Iac != nil && *productConfig.Iac,
			Oss:       productConfig.Oss != nil && *productConfig.Oss,
		}
	}

	// Extract scan configuration
	if ideConfig.ScanConfig != nil && ideConfig.ScanConfig.Automatic != nil {
		config.AutoScan = *ideConfig.ScanConfig.Automatic
	}

	// Extract trust configuration
	if ideConfig.TrustConfig != nil && ideConfig.TrustConfig.TrustedFolders != nil {
		config.TrustedFolders = *ideConfig.TrustConfig.TrustedFolders
	}
}

// extractProxyConfig extracts proxy configuration
func extractProxyConfig(configData *v20241015.ConfigData, config *Configuration) {
	if configData.ProxyConfig == nil {
		return
	}

	proxyConfig := configData.ProxyConfig
	config.ProxyConfig = &ProxyConfig{}

	if proxyConfig.Http != nil {
		config.ProxyConfig.Http = *proxyConfig.Http
	}
	if proxyConfig.Https != nil {
		config.ProxyConfig.Https = *proxyConfig.Https
	}
	if proxyConfig.Insecure != nil {
		config.ProxyConfig.Insecure = *proxyConfig.Insecure
	}
	if proxyConfig.NoProxy != nil {
		config.ProxyConfig.NoProxy = *proxyConfig.NoProxy
	}
}

// findDefaultOrganizationFromList finds the default organization from a list
func findDefaultOrganizationFromList(organizations []v20241015.Organization) *v20241015.Organization {
	for _, org := range organizations {
		if org.IsDefault != nil && *org.IsDefault {
			return &org
		}
	}
	if len(organizations) > 0 {
		return &organizations[0]
	}
	return nil
}

// findProjectRoot walks up the directory tree from the given path to find a git repository root
func findProjectRoot(startPath string) string {
	currentPath := startPath

	for {
		// Check if current directory is a git repository
		gitDir := filepath.Join(currentPath, ".git")
		if _, err := os.Stat(gitDir); err == nil {
			return currentPath
		}

		// Move up one directory
		parentPath := filepath.Dir(currentPath)
		if parentPath == currentPath {
			// Reached filesystem root
			break
		}
		currentPath = parentPath
	}

	return ""
}

// findOrganizationFromFolderConfigs looks for an organization in folder configs that matches the remote URL
func findOrganizationFromFolderConfigs(ldxConfig *v20241015.ConfigResponse, remoteUrl string) string {
	if ldxConfig.Data.Attributes.ConfigData.FolderConfigs == nil {
		return ""
	}
	for _, folderConfig := range *ldxConfig.Data.Attributes.ConfigData.FolderConfigs {
		if folderConfig.RemoteUrl == remoteUrl && folderConfig.Organizations != nil && len(*folderConfig.Organizations) > 0 {
			// Return the first organization from the matching folder config
			return (*folderConfig.Organizations)[0].Id
		}
	}
	return ""
}

// findDefaultOrganization finds the default organization from the main organizations list
func findDefaultOrganization(ldxConfig *v20241015.ConfigResponse) string {
	if ldxConfig.Data.Attributes.ConfigData.Organizations == nil {
		return ""
	}

	for _, org := range *ldxConfig.Data.Attributes.ConfigData.Organizations {
		if org.IsDefault != nil && *org.IsDefault {
			return org.Id
		}
	}

	// If no default organization found, return the first one
	if len(*ldxConfig.Data.Attributes.ConfigData.Organizations) > 0 {
		return (*ldxConfig.Data.Attributes.ConfigData.Organizations)[0].Id
	}

	return ""
}
