package llm

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

// Option configures how a provider is built. All options are optional; the
// zero configuration yields real behaviour with langchaingo's default transport
// and no bedrock app id.
type Option func(*options)

type options struct {
	networkAccess networking.NetworkAccess
	logger        *zerolog.Logger
	bedrockAppID  string
}

// WithNetworkAccess supplies the shared HTTP transport used for provider
// traffic. The unauthorized client is used (proxy/CA/FIPS hardening WITHOUT
// Snyk auth headers) — Snyk credentials must never be sent to a third-party LLM
// endpoint. When omitted, langchaingo's default transport is used.
func WithNetworkAccess(na networking.NetworkAccess) Option {
	return func(o *options) { o.networkAccess = na }
}

// WithLogger supplies a logger for diagnostic output. Currently unused by the
// adapters; accepted so callers can wire it uniformly and future adapters can
// log without a signature change.
func WithLogger(l *zerolog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithBedrockAppID sets the AWS User-Agent "app/<id>" token for the bedrock
// provider so its traffic can be attributed downstream. Empty (the default)
// leaves the User-Agent unbranded, keeping this package vendor-neutral.
func WithBedrockAppID(id string) Option {
	return func(o *options) { o.bedrockAppID = id }
}

// baseTransport returns the shared base RoundTripper for provider HTTP clients,
// or nil to fall back to langchaingo's default transport.
func (o *options) baseTransport() http.RoundTripper {
	if o.networkAccess == nil {
		return nil
	}
	if c := o.networkAccess.GetUnauthorizedHttpClient(); c != nil {
		return c.Transport
	}
	return nil
}

// requiredSetting is a config key that must be non-empty for a provider, with
// the env-var name used in the error message when it is missing.
type requiredSetting struct {
	key string
	env string
}

// providerDef holds everything the package needs to know about one provider.
// Adding a provider means adding one entry here; nothing else changes.
type providerDef struct {
	// defaultModel is used when the model config key is unset. Empty means the
	// model is required (ollama and litellm have no sensible default).
	defaultModel string

	// apiKeyKey is the canonical config key holding the API key, or "" when the
	// provider uses no API key (ollama runs locally; vertex/bedrock use ADC/AWS).
	apiKeyKey string

	// required lists settings that must be non-empty (e.g. LITELLM_BASE_URL,
	// vertex project/location).
	required []requiredSetting

	// baseURLKey optionally names a config key holding a base-URL override. It
	// also serves as an auto-detect signal: a provider can be picked without its
	// API key because the base URL may front a gateway that supplies auth.
	baseURLKey string

	// autoDetect marks providers Resolve can pick when no provider is configured
	// (only API-key providers with a known key/base-URL).
	autoDetect bool

	// build constructs the adapter, reading credentials/settings from config.
	build func(config configuration.Configuration, res Resolution, o *options) (Provider, error)
}

// providers is the single source of truth for all supported LLM backends.
var providers = map[string]providerDef{
	"anthropic": {
		defaultModel: "claude-sonnet-4-6",
		apiKeyKey:    CONFIG_ANTHROPIC_API_KEY,
		baseURLKey:   CONFIG_ANTHROPIC_BASE_URL,
		autoDetect:   true,
		build: func(config configuration.Configuration, _ Resolution, o *options) (Provider, error) {
			return NewAnthropicAdapter(
				config.GetString(CONFIG_ANTHROPIC_API_KEY),
				config.GetString(CONFIG_ANTHROPIC_BASE_URL),
				extraHeaders(config),
				o.baseTransport(),
			)
		},
	},
	"openai": {
		defaultModel: "gpt-4o",
		apiKeyKey:    CONFIG_OPENAI_API_KEY,
		autoDetect:   true,
		build: func(config configuration.Configuration, _ Resolution, o *options) (Provider, error) {
			return NewOpenAIAdapter(
				config.GetString(CONFIG_OPENAI_API_KEY),
				"",
				extraHeaders(config),
				o.baseTransport(),
			)
		},
	},
	"ollama": {
		build: func(config configuration.Configuration, res Resolution, o *options) (Provider, error) {
			return NewOllamaAdapter(res.Model, config.GetString(CONFIG_OLLAMA_HOST), o.baseTransport())
		},
	},
	"vertex": {
		defaultModel: "gemini-2.5-flash",
		required: []requiredSetting{
			{CONFIG_VERTEX_PROJECT, EnvVertexProject},
			{CONFIG_VERTEX_LOCATION, EnvVertexLocation},
		},
		baseURLKey: CONFIG_VERTEX_BASE_URL,
		build: func(config configuration.Configuration, res Resolution, o *options) (Provider, error) {
			return NewVertexAdapter(
				res.Model,
				config.GetString(CONFIG_VERTEX_PROJECT),
				config.GetString(CONFIG_VERTEX_LOCATION),
				config.GetString(CONFIG_VERTEX_BASE_URL),
				config.GetString(CONFIG_VERTEX_AUTH_TOKEN),
				extraHeaders(config),
				o.baseTransport(),
			)
		},
	},
	"litellm": {
		apiKeyKey: CONFIG_LITELLM_API_KEY,
		required:  []requiredSetting{{CONFIG_LITELLM_BASE_URL, EnvLiteLLMBaseURL}},
		build: func(config configuration.Configuration, _ Resolution, o *options) (Provider, error) {
			return NewLiteLLMAdapter(
				config.GetString(CONFIG_LITELLM_API_KEY),
				config.GetString(CONFIG_LITELLM_BASE_URL),
				extraHeaders(config),
				o.baseTransport(),
			)
		},
	},
	"bedrock": {
		// Amazon Bedrock. Model ids are region/account-specific (and newer Claude
		// models are reached via cross-region inference profiles), so we default to
		// a broadly-available Claude 3.5 Sonnet id; override with the model key.
		defaultModel: "anthropic.claude-3-5-sonnet-20241022-v2:0",
		// Auth is the standard AWS credential chain (no API key). Region is
		// resolved by the AWS SDK from AWS_REGION / profile when the key is unset,
		// so it is not a hard requirement here.
		build: func(config configuration.Configuration, res Resolution, o *options) (Provider, error) {
			return NewBedrockAdapter(res.Model, config.GetString(CONFIG_AWS_REGION), o.bedrockAppID)
		},
	},
}

// Resolution is the outcome of resolving configuration into a concrete provider
// choice. Callers use it for telemetry (provider name + model) and pass it to
// New.
type Resolution struct {
	Provider string // resolved provider name
	Model    string // resolved model id (default applied; may be empty)
}

// Resolve picks the LLM provider from configuration.
//
// When CONFIG_PROVIDER is set, it must be one of the supported providers and
// all required settings must be non-empty. When unset, we auto-detect: prefer
// an Anthropic key (or base URL), then an OpenAI key; error if neither is set.
// Auto-detect deliberately does NOT pick ollama, vertex, litellm, or bedrock —
// they must be opted into explicitly.
func Resolve(config configuration.Configuration) (Resolution, error) {
	RegisterConfiguration(config)

	name := strings.TrimSpace(config.GetString(CONFIG_PROVIDER))
	if name != "" {
		def, ok := providers[name]
		if !ok {
			return Resolution{}, fmt.Errorf("unknown provider %q (want anthropic, openai, ollama, vertex, litellm, or bedrock)", name)
		}
		for _, rs := range def.required {
			if config.GetString(rs.key) == "" {
				return Resolution{}, fmt.Errorf("%s is not set in the environment", rs.env)
			}
		}
		return Resolution{Provider: name, Model: modelFor(config, def)}, nil
	}

	for _, n := range []string{"anthropic", "openai"} {
		def := providers[n]
		if !def.autoDetect {
			continue
		}
		if def.apiKeyKey != "" && config.GetString(def.apiKeyKey) != "" {
			return Resolution{Provider: n, Model: modelFor(config, def)}, nil
		}
		// A configured base URL is enough to pick the provider even without a
		// key — the gateway it points at may supply auth.
		if def.baseURLKey != "" && config.GetString(def.baseURLKey) != "" {
			return Resolution{Provider: n, Model: modelFor(config, def)}, nil
		}
	}
	return Resolution{}, fmt.Errorf("no LLM provider configured (set ANTHROPIC_API_KEY or OPENAI_API_KEY, set ANTHROPIC_BASE_URL, or set the provider)")
}

// New builds the provider adapter for an already-resolved choice.
func New(config configuration.Configuration, res Resolution, opts ...Option) (Provider, error) {
	RegisterConfiguration(config)
	def, ok := providers[res.Provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", res.Provider)
	}
	if res.Model == "" && def.defaultModel == "" {
		return nil, fmt.Errorf("%s: model is required (no default model for this provider)", res.Provider)
	}
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return def.build(config, res, o)
}

// NewFromConfig resolves the provider from configuration and builds it in one
// step. Use New with a Resolution when the resolved provider/model are needed
// separately (e.g. for telemetry).
func NewFromConfig(config configuration.Configuration, opts ...Option) (Provider, error) {
	res, err := Resolve(config)
	if err != nil {
		return nil, err
	}
	return New(config, res, opts...)
}

// modelFor returns the configured model, falling back to the provider default.
func modelFor(config configuration.Configuration, def providerDef) string {
	if m := strings.TrimSpace(config.GetString(CONFIG_MODEL)); m != "" {
		return m
	}
	return def.defaultModel
}

// extraHeaders reads and parses the extra-headers config value.
func extraHeaders(config configuration.Configuration) http.Header {
	return parseExtraHeaders(config.GetString(CONFIG_EXTRA_HEADERS))
}
