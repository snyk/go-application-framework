package llm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/llm"
)

// NewBedrockAdapter constructs offline: it loads AWS config and creates a
// bedrockruntime client (no network, credentials resolved lazily on first call),
// then wraps the langchaingo bedrock LLM in a LangchainAdapter named "bedrock".
func TestNewBedrockAdapter_Constructs(t *testing.T) {
	a, err := llm.NewBedrockAdapter("anthropic.claude-3-5-sonnet-20241022-v2:0", "us-east-1", "")
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "bedrock", a.Name())
}

// An empty region must still construct — the AWS SDK resolves the region from
// the environment/active profile at that point.
func TestNewBedrockAdapter_NoRegionStillConstructs(t *testing.T) {
	a, err := llm.NewBedrockAdapter("anthropic.claude-3-5-sonnet-20241022-v2:0", "", "")
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "bedrock", a.Name())
}

// An empty model is tolerated at construction (langchaingo falls back to its
// default model id); the CLI supplies a default via the provider registry.
func TestNewBedrockAdapter_EmptyModelConstructs(t *testing.T) {
	a, err := llm.NewBedrockAdapter("", "us-east-1", "")
	require.NoError(t, err)
	require.NotNil(t, a)
}

// A non-empty app id still constructs (it flows into the AWS User-Agent).
func TestNewBedrockAdapter_WithAppIDConstructs(t *testing.T) {
	a, err := llm.NewBedrockAdapter("anthropic.claude-3-5-sonnet-20241022-v2:0", "us-east-1", "SOME_APP_ID")
	require.NoError(t, err)
	require.NotNil(t, a)
}
