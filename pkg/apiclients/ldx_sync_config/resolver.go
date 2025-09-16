package ldx_sync_config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

// LdxSyncConfigResult contains the result of LDX-Sync config retrieval
type LdxSyncConfigResult struct {
	Config      *Configuration
	RemoteUrl   string
	ProjectRoot string
	Error       error
}

// getLdxSyncConfig retrieves LDX-Sync configuration for the current project
func getLdxSyncConfig(config configuration.Configuration, ldxClient LdxSyncConfigClient) LdxSyncConfigResult {
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

	params := GetConfigurationParams{RemoteUrl: remoteUrl}
	ldxConfig, err := ldxClient.GetConfiguration(context.Background(), params)
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
func TryResolveOrganization(config configuration.Configuration, ldxClient LdxSyncConfigClient, logger *zerolog.Logger) string {
	result := getLdxSyncConfig(config, ldxClient)
	if result.Error != nil {
		logger.Debug().Err(result.Error).Msg("LDX-Sync resolution failed, falling back to default")
		return ""
	}

	// Use the organization directly from the high-level Configuration
	orgId := result.Config.Organization
	if orgId != "" {
		logger.Debug().Str("orgId", orgId).Str("remoteUrl", result.RemoteUrl).Str("projectRoot", result.ProjectRoot).Msg("Resolved organization via LDX-Sync")
		return orgId
	}

	logger.Debug().Str("remoteUrl", result.RemoteUrl).Msg("No matching organization found in LDX-Sync config, falling back to default")
	return ""
}

// GetConfig retrieves LDX-Sync configuration for the current project
func GetConfig(config configuration.Configuration, ldxClient LdxSyncConfigClient, logger *zerolog.Logger) (*Configuration, error) {
	result := getLdxSyncConfig(config, ldxClient)
	if result.Error != nil {
		return nil, result.Error
	}

	// Return the high-level Configuration directly
	return result.Config, nil
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
