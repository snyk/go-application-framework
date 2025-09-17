package ldx_sync_config

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestTryResolveOrganization(t *testing.T) {
	logger := zerolog.Nop()

	// Test with empty input directory
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set("INPUT_DIRECTORY", "")

	// Test with nil client - this should fail gracefully
	result := TryResolveOrganization(config, nil, &logger)
	assert.Equal(t, "", result)
}

func TestGetConfig(t *testing.T) {
	logger := zerolog.Nop()

	// Test with empty input directory
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set("INPUT_DIRECTORY", "")

	// Test with nil client - this should fail gracefully
	_, err := GetConfig(config, nil, &logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no input directory specified")
}
