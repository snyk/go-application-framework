package ldx_sync

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestTryResolveOrganization(t *testing.T) {
	logger := zerolog.Nop()

	// Test with empty input directory
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set("INPUT_DIRECTORY", "")

	result := TryResolveOrganization(config, nil, &logger)
	assert.Equal(t, "", result)
}

func TestGetConfig(t *testing.T) {
	logger := zerolog.Nop()

	// Test with empty input directory
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set("INPUT_DIRECTORY", "")

	_, err := GetConfig(config, nil, &logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no input directory specified")
}

func TestFindOrganizationFromFolderConfigs(t *testing.T) {
	t.Run("nil folder configs", func(t *testing.T) {
		ldxConfig := &v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Attributes: v20241015.ConfigAttributes{
					ConfigData: v20241015.ConfigData{
						FolderConfigs: nil,
					},
				},
			},
		}
		result := findOrganizationFromFolderConfigs(ldxConfig, "some-url")
		assert.Equal(t, "", result)
	})

	t.Run("matching folder config found", func(t *testing.T) {
		remoteUrl := "https://github.com/test/repo.git"
		orgId := "org-123"
		ldxConfig := &v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Attributes: v20241015.ConfigAttributes{
					ConfigData: v20241015.ConfigData{
						FolderConfigs: &[]v20241015.FolderConfig{
							{
								RemoteUrl: remoteUrl,
								Organizations: &[]v20241015.Organization{
									{Id: orgId},
								},
							},
						},
					},
				},
			},
		}
		result := findOrganizationFromFolderConfigs(ldxConfig, remoteUrl)
		assert.Equal(t, orgId, result)
	})

	t.Run("no matching folder config", func(t *testing.T) {
		ldxConfig := &v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Attributes: v20241015.ConfigAttributes{
					ConfigData: v20241015.ConfigData{
						FolderConfigs: &[]v20241015.FolderConfig{
							{
								RemoteUrl: "https://github.com/another/repo.git",
								Organizations: &[]v20241015.Organization{
									{Id: "org-456"},
								},
							},
						},
					},
				},
			},
		}
		result := findOrganizationFromFolderConfigs(ldxConfig, "https://github.com/test/repo.git")
		assert.Equal(t, "", result)
	})
}

func TestFindDefaultOrganization(t *testing.T) {
	t.Run("nil organizations", func(t *testing.T) {
		ldxConfig := &v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Attributes: v20241015.ConfigAttributes{
					ConfigData: v20241015.ConfigData{
						Organizations: nil,
					},
				},
			},
		}
		result := findDefaultOrganization(ldxConfig)
		assert.Equal(t, "", result)
	})

	t.Run("default organization found", func(t *testing.T) {
		orgId := "default-org-123"
		isDefault := true
		ldxConfig := &v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Attributes: v20241015.ConfigAttributes{
					ConfigData: v20241015.ConfigData{
						Organizations: &[]v20241015.Organization{
							{Id: "org-456"},
							{Id: orgId, IsDefault: &isDefault},
						},
					},
				},
			},
		}
		result := findDefaultOrganization(ldxConfig)
		assert.Equal(t, orgId, result)
	})

	t.Run("no default organization, return first", func(t *testing.T) {
		orgId := "first-org-789"
		ldxConfig := &v20241015.ConfigResponse{
			Data: v20241015.ConfigResource{
				Attributes: v20241015.ConfigAttributes{
					ConfigData: v20241015.ConfigData{
						Organizations: &[]v20241015.Organization{
							{Id: orgId},
							{Id: "org-abc"},
						},
					},
				},
			},
		}
		result := findDefaultOrganization(ldxConfig)
		assert.Equal(t, orgId, result)
	})
}

func TestFindProjectRoot(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		result := findProjectRoot("")
		assert.Equal(t, "", result)
	})

	t.Run("non-existent path", func(t *testing.T) {
		result := findProjectRoot("/non/existent/path")
		assert.Equal(t, "", result)
	})
}
