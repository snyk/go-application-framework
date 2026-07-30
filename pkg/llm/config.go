package llm

import (
	"net/http"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Environment variables users set to configure the LLM providers. They are the
// same names the vendors' own CLIs/SDKs use, kept stable so existing setups
// keep working after this logic moved into GAF. RegisterConfiguration binds
// each onto its canonical CONFIG_* key.
const (
	EnvAnthropicAPIKey  = "ANTHROPIC_API_KEY"
	EnvAnthropicBaseURL = "ANTHROPIC_BASE_URL"
	EnvOpenAIAPIKey     = "OPENAI_API_KEY"
	EnvOllamaHost       = "OLLAMA_HOST"
	EnvVertexProject    = "GOOGLE_CLOUD_PROJECT"
	EnvVertexLocation   = "GOOGLE_CLOUD_LOCATION"
	EnvVertexBaseURL    = "VERTEX_BASE_URL"
	EnvVertexAuthToken  = "VERTEX_AUTH_TOKEN"
	EnvAWSRegion        = "AWS_REGION"
	EnvLiteLLMBaseURL   = "LITELLM_BASE_URL"
	EnvLiteLLMAPIKey    = "LITELLM_API_KEY"

	// EnvExtraHeaders carries comma-separated key=value headers added to every
	// cloud provider's requests — for a gateway that requires custom headers
	// beyond auth (e.g. an end-user identity header). Example:
	// SNYK_LLM_EXTRA_HEADERS="x-user-id=jsmith,x-org-id=acme".
	EnvExtraHeaders = "SNYK_LLM_EXTRA_HEADERS"
	// EnvExtraHeadersLegacy is the pre-GAF name (from the remy extension). It is
	// kept as an alternative key so existing setups keep working; prefer
	// EnvExtraHeaders in new configurations.
	EnvExtraHeadersLegacy = "REMY_EXTRA_HEADERS"
)

// Canonical configuration keys. Reading these resolves the matching env var via
// the alternative-key wiring in RegisterConfiguration; they are the stable
// handles a programmatic caller can Set directly.
const (
	CONFIG_PROVIDER           = "snyk_llm_provider"
	CONFIG_MODEL              = "snyk_llm_model"
	CONFIG_ANTHROPIC_API_KEY  = "snyk_llm_anthropic_api_key"
	CONFIG_ANTHROPIC_BASE_URL = "snyk_llm_anthropic_base_url"
	CONFIG_OPENAI_API_KEY     = "snyk_llm_openai_api_key"
	CONFIG_OLLAMA_HOST        = "snyk_llm_ollama_host"
	CONFIG_VERTEX_PROJECT     = "snyk_llm_vertex_project"
	CONFIG_VERTEX_LOCATION    = "snyk_llm_vertex_location"
	CONFIG_VERTEX_BASE_URL    = "snyk_llm_vertex_base_url"
	CONFIG_VERTEX_AUTH_TOKEN  = "snyk_llm_vertex_auth_token"
	CONFIG_AWS_REGION         = "snyk_llm_aws_region"
	CONFIG_LITELLM_BASE_URL   = "snyk_llm_litellm_base_url"
	CONFIG_LITELLM_API_KEY    = "snyk_llm_litellm_api_key"
	CONFIG_EXTRA_HEADERS      = "snyk_llm_extra_headers"
)

// defaultOllamaHost is the local Ollama endpoint used when neither the config
// key nor OLLAMA_HOST is set. It is the conventional address the ollama CLI/SDK
// use.
const defaultOllamaHost = "http://localhost:11434"

// RegisterConfiguration wires the LLM config keys onto their env vars: it marks
// the env-var names as supported (so they resolve even without AutomaticEnv),
// attaches each env name as an alternative key of its canonical CONFIG_* key,
// and sets the Ollama-host default. It is safe to call more than once. API keys
// are NOT persisted to storage — they stay env-only, read on demand.
func RegisterConfiguration(config configuration.Configuration) {
	if config == nil {
		return
	}

	config.SetSupportedEnvVars(
		EnvAnthropicAPIKey, EnvAnthropicBaseURL,
		EnvOpenAIAPIKey,
		EnvOllamaHost,
		EnvVertexProject, EnvVertexLocation, EnvVertexBaseURL, EnvVertexAuthToken,
		EnvAWSRegion,
		EnvLiteLLMBaseURL, EnvLiteLLMAPIKey,
		EnvExtraHeaders, EnvExtraHeadersLegacy,
	)

	config.AddAlternativeKeys(CONFIG_ANTHROPIC_API_KEY, []string{EnvAnthropicAPIKey})
	config.AddAlternativeKeys(CONFIG_ANTHROPIC_BASE_URL, []string{EnvAnthropicBaseURL})
	config.AddAlternativeKeys(CONFIG_OPENAI_API_KEY, []string{EnvOpenAIAPIKey})
	config.AddAlternativeKeys(CONFIG_OLLAMA_HOST, []string{EnvOllamaHost})
	config.AddAlternativeKeys(CONFIG_VERTEX_PROJECT, []string{EnvVertexProject})
	config.AddAlternativeKeys(CONFIG_VERTEX_LOCATION, []string{EnvVertexLocation})
	config.AddAlternativeKeys(CONFIG_VERTEX_BASE_URL, []string{EnvVertexBaseURL})
	config.AddAlternativeKeys(CONFIG_VERTEX_AUTH_TOKEN, []string{EnvVertexAuthToken})
	config.AddAlternativeKeys(CONFIG_AWS_REGION, []string{EnvAWSRegion})
	config.AddAlternativeKeys(CONFIG_LITELLM_BASE_URL, []string{EnvLiteLLMBaseURL})
	config.AddAlternativeKeys(CONFIG_LITELLM_API_KEY, []string{EnvLiteLLMAPIKey})
	config.AddAlternativeKeys(CONFIG_EXTRA_HEADERS, []string{EnvExtraHeaders, EnvExtraHeadersLegacy})

	config.AddDefaultValue(CONFIG_OLLAMA_HOST, configuration.StandardDefaultValueFunction(defaultOllamaHost))
}

// parseExtraHeaders turns the comma-separated key=value string into an
// http.Header. Returns nil when raw is empty. Pairs without "=" or with an
// empty key are skipped; values cannot contain commas (the pair separator).
func parseExtraHeaders(raw string) http.Header {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	h := http.Header{}
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		h.Add(k, strings.TrimSpace(v))
	}
	if len(h) == 0 {
		return nil
	}
	return h
}
