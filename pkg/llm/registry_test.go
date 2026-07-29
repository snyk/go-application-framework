package llm_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/llm"
)

// newConfig returns an in-memory config with the LLM keys registered and the
// auto-detect env vars cleared, so tests are deterministic regardless of the
// host environment (NewInMemory enables AutomaticEnv, which would otherwise let
// an ambient ANTHROPIC_API_KEY leak in).
func newConfig(t *testing.T) configuration.Configuration {
	t.Helper()
	t.Setenv(llm.EnvAnthropicAPIKey, "")
	t.Setenv(llm.EnvOpenAIAPIKey, "")
	t.Setenv(llm.EnvAnthropicBaseURL, "")
	c := configuration.NewInMemory()
	llm.RegisterConfiguration(c)
	return c
}

func TestResolve_AutoDetectPrefersAnthropic(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_ANTHROPIC_API_KEY, "ak")
	c.Set(llm.CONFIG_OPENAI_API_KEY, "ok")

	res, err := llm.Resolve(c)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", res.Provider)
	assert.Equal(t, "claude-sonnet-4-6", res.Model, "default model applied")
}

func TestResolve_AutoDetectFallsBackToOpenAI(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_OPENAI_API_KEY, "ok")

	res, err := llm.Resolve(c)
	require.NoError(t, err)
	assert.Equal(t, "openai", res.Provider)
	assert.Equal(t, "gpt-4o", res.Model)
}

func TestResolve_AutoDetectByAnthropicBaseURL(t *testing.T) {
	// A configured base URL is enough to pick anthropic even without a key —
	// the gateway it points at may supply auth.
	c := newConfig(t)
	c.Set(llm.CONFIG_ANTHROPIC_BASE_URL, "https://gw.example.com")

	res, err := llm.Resolve(c)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", res.Provider)
}

func TestResolve_NoProviderConfigured(t *testing.T) {
	c := newConfig(t)
	_, err := llm.Resolve(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no LLM provider configured")
}

func TestResolve_UnknownProvider(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_PROVIDER, "definitely-not-a-provider")
	_, err := llm.Resolve(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestResolve_LiteLLMRequiresBaseURL(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_PROVIDER, "litellm")
	_, err := llm.Resolve(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LITELLM_BASE_URL")
}

func TestResolve_VertexRequiresProjectAndLocation(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_PROVIDER, "vertex")
	_, err := llm.Resolve(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GOOGLE_CLOUD_PROJECT")

	c.Set(llm.CONFIG_VERTEX_PROJECT, "p")
	_, err = llm.Resolve(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GOOGLE_CLOUD_LOCATION")
}

func TestResolve_ExplicitModelOverridesDefault(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_PROVIDER, "anthropic")
	c.Set(llm.CONFIG_ANTHROPIC_API_KEY, "ak")
	c.Set(llm.CONFIG_MODEL, "claude-opus-4-8")

	res, err := llm.Resolve(c)
	require.NoError(t, err)
	assert.Equal(t, "claude-opus-4-8", res.Model)
}

func TestResolve_EnvVarAlternativeKeys(t *testing.T) {
	// Reading the canonical key must fall through to the vendor env var name, so
	// existing setups (env-only) keep working.
	c := configuration.NewInMemory()
	llm.RegisterConfiguration(c)
	t.Setenv(llm.EnvAnthropicAPIKey, "from-env")

	res, err := llm.Resolve(c)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", res.Provider)
	assert.Equal(t, "from-env", c.GetString(llm.CONFIG_ANTHROPIC_API_KEY))
}

func TestNew_OllamaRequiresModel(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_PROVIDER, "ollama")
	// No model set and ollama has no default → New must reject.
	res, err := llm.Resolve(c)
	require.NoError(t, err)
	_, err = llm.New(c, res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model is required")
}

func TestNewFromConfig_BuildsAnthropic(t *testing.T) {
	c := newConfig(t)
	c.Set(llm.CONFIG_ANTHROPIC_API_KEY, "ak")

	p, err := llm.NewFromConfig(c)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "anthropic", p.Name())
}
