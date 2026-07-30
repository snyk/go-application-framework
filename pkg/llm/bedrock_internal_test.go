package llm

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A non-empty app id must set LoadOptions.AppID (it becomes an "app/<id>" token
// in the AWS User-Agent, so traffic can be attributed downstream). The package
// ships unbranded — the id is supplied by the caller, not hardcoded here.
func TestBedrockConfigOptions_SetsAppIDWhenProvided(t *testing.T) {
	var lo config.LoadOptions
	for _, opt := range bedrockConfigOptions("us-east-1", "MY_APP_ID") {
		require.NoError(t, opt(&lo))
	}
	assert.Equal(t, "MY_APP_ID", lo.AppID)
	assert.Equal(t, "us-east-1", lo.Region)
}

// An empty app id leaves the User-Agent unbranded (AppID unset), and an empty
// region stays unset (the SDK resolves it from env/profile).
func TestBedrockConfigOptions_EmptyAppIDAndRegion(t *testing.T) {
	var lo config.LoadOptions
	for _, opt := range bedrockConfigOptions("", "") {
		require.NoError(t, opt(&lo))
	}
	assert.Empty(t, lo.AppID)
	assert.Empty(t, lo.Region)
}
