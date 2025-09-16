package ldx_sync_config

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// mockLdxSyncConfigClient is a mock implementation that returns errors
type mockLdxSyncConfigClient struct {
	err error
}

func (c *mockLdxSyncConfigClient) GetConfiguration(ctx context.Context, params GetConfigurationParams) (*Configuration, error) {
	return nil, c.err
}

func TestTryResolveOrganization(t *testing.T) {
	logger := zerolog.Nop()

	// Test with empty input directory
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set("INPUT_DIRECTORY", "")

	// Create a mock LdxSyncConfigClient
	mockClient := &mockLdxSyncConfigClient{err: assert.AnError}
	result := TryResolveOrganization(config, mockClient, &logger)
	assert.Equal(t, "", result)
}

func TestGetConfig(t *testing.T) {
	logger := zerolog.Nop()

	// Test with empty input directory
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set("INPUT_DIRECTORY", "")

	// Create a mock LdxSyncConfigClient
	mockClient := &mockLdxSyncConfigClient{err: assert.AnError}
	_, err := GetConfig(config, mockClient, &logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no input directory specified")
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
