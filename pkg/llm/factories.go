package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tmc/langchaingo/httputil"
	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/tmc/langchaingo/llms/openai"
)

// strippedBodyFields lists top-level JSON keys removed from every outgoing
// request body of the langchaingo-backed adapters. langchaingo hardcodes
// "temperature" into the anthropic and openai request payloads with no
// omitempty, so it is sent as temperature:0 even when we never set it — and
// current models reject the parameter ("temperature is deprecated for this
// model"). We drop it on the wire so it is never sent. Deleting a
// provider-deprecated field is safe: the model falls back to its own default.
var strippedBodyFields = []string{"temperature"}

// Per-vendor factories that build the right langchaingo llms.Model and wrap
// it in a LangchainAdapter. All return *LangchainAdapter so they share a single
// mapping implementation; nothing here knows about wire formats.

// missingKeyPlaceholder is handed to langchaingo when no API key is set.
// langchaingo's anthropic.New / openai.New refuse to construct without a
// non-empty token, but we deliberately do not fail at startup on a missing key:
// a base-URL gateway may authenticate by other means. The placeholder satisfies
// the construct-time guard; for anthropic we then strip the x-api-key header on
// the way out (see headerTransport) so the placeholder never reaches the endpoint.
const missingKeyPlaceholder = "no-api-key-set"

// baseOrDefault returns base, or langchaingo's default transport (which adds the
// langchaingo User-Agent) when base is nil. base is the shared transport a
// caller threads in via WithNetworkAccess — networking.GetUnauthorizedHttpClient's
// transport, which applies proxy/CA/FIPS without Snyk auth headers.
func baseOrDefault(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		return httputil.DefaultTransport
	}
	return base
}

// headerTransport is an http.RoundTripper that strips and/or adds request
// headers, then delegates to base (nil → http.DefaultTransport). This is the
// idiomatic transport-layer seam for header injection: it composes with any
// underlying transport — langchaingo's httputil.DefaultTransport (which adds the
// langchaingo User-Agent), the vertex/bearer path, or a TLS/CA-configured
// networking transport. We use it to (a) strip the placeholder auth header when
// no API key is set — so it never reaches a gateway that authenticates by other
// means — and (b) add caller-supplied gateway headers (auth, identity).
// Stripping runs first so an explicit header in add still wins.
type headerTransport struct {
	base      http.RoundTripper
	add       http.Header
	strip     []string
	stripBody []string // top-level JSON keys removed from the request body
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context()) // RoundTrippers must not mutate the caller's request
	for _, h := range t.strip {
		req.Header.Del(h)
	}
	for k, vs := range t.add {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if len(t.stripBody) > 0 && req.Body != nil {
		if err := stripJSONBodyFields(req, t.stripBody); err != nil {
			return nil, err
		}
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// stripJSONBodyFields rewrites req.Body, removing the named top-level JSON keys.
// It reads the whole body (safe here — LLM chat requests are non-streaming and
// small) and resets Body, ContentLength, and GetBody so retries/redirects
// re-send the modified payload. A non-JSON or unparseable body is passed
// through unchanged, and every key other than those removed is preserved
// verbatim (json.RawMessage), so nothing else is reformatted.
func stripJSONBodyFields(req *http.Request, fields []string) error {
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return err
	}
	out := raw
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		changed := false
		for _, f := range fields {
			if _, ok := m[f]; ok {
				delete(m, f)
				changed = true
			}
		}
		if changed {
			if b, mErr := json.Marshal(m); mErr == nil {
				out = b
			}
		}
	}
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(out)), nil }
	return nil
}

// headerClient returns an *http.Client whose transport adds/strips the given
// headers and strips the given JSON body fields over base, or nil when there is
// nothing to do (so callers only override the HTTP client when needed).
// *http.Client satisfies langchaingo's Doer interfaces.
func headerClient(base http.RoundTripper, add http.Header, strip, stripBody []string) *http.Client {
	if len(add) == 0 && len(strip) == 0 && len(stripBody) == 0 {
		return nil
	}
	return &http.Client{Transport: &headerTransport{base: base, add: add, strip: strip, stripBody: stripBody}}
}

// Auth headers each langchaingo client writes the token into, stripped when no
// key is configured. anthropic uses x-api-key; openai uses Authorization, plus
// api-key in Azure mode.
var (
	anthropicAuthHeaders = []string{"x-api-key"}
	openAIAuthHeaders    = []string{"Authorization", "api-key"}
)

// tokenOrPlaceholder returns apiKey, or the placeholder when apiKey is empty,
// so the langchaingo-backed factories always construct.
func tokenOrPlaceholder(apiKey string) string {
	if apiKey == "" {
		return missingKeyPlaceholder
	}
	return apiKey
}

// NewAnthropicAdapter builds a LangchainAdapter backed by
// github.com/tmc/langchaingo/llms/anthropic. baseURL is optional — empty means
// use Anthropic's default endpoint. A missing apiKey is tolerated (see
// tokenOrPlaceholder). base is the shared HTTP transport (nil = langchaingo default).
func NewAnthropicAdapter(apiKey, baseURL string, extra http.Header, base http.RoundTripper) (*LangchainAdapter, error) {
	opts := []anthropic.Option{anthropic.WithToken(tokenOrPlaceholder(apiKey))}
	if baseURL != "" {
		opts = append(opts, anthropic.WithBaseURL(normalizeAnthropicBaseURL(baseURL)))
	}
	// No key: the placeholder above only exists to satisfy langchaingo's
	// construct-time guard; strip x-api-key on the wire so a base-URL gateway
	// applies its own auth. Also add any caller-supplied gateway headers.
	var strip []string
	if apiKey == "" {
		strip = anthropicAuthHeaders
	}
	if c := headerClient(baseOrDefault(base), extra, strip, strippedBodyFields); c != nil {
		opts = append(opts, anthropic.WithHTTPClient(c))
	}
	llm, err := anthropic.New(opts...)
	if err != nil {
		return nil, err
	}
	return NewLangchainAdapter("anthropic", llm), nil
}

// NewOpenAIAdapter builds a LangchainAdapter backed by
// github.com/tmc/langchaingo/llms/openai. baseURL is optional.
func NewOpenAIAdapter(apiKey, baseURL string, extra http.Header, base http.RoundTripper) (*LangchainAdapter, error) {
	opts := []openai.Option{openai.WithToken(tokenOrPlaceholder(apiKey))}
	if baseURL != "" {
		opts = append(opts, openai.WithBaseURL(baseURL))
	}
	var strip []string
	if apiKey == "" {
		strip = openAIAuthHeaders
	}
	if c := headerClient(baseOrDefault(base), extra, strip, strippedBodyFields); c != nil {
		opts = append(opts, openai.WithHTTPClient(c))
	}
	llm, err := openai.New(opts...)
	if err != nil {
		return nil, err
	}
	a := NewLangchainAdapter("openai", llm)
	a.splitToolResults = true // OpenAI requires one part per tool message
	return a, nil
}

// NewLiteLLMAdapter builds a LangchainAdapter for models served by a LiteLLM
// proxy. LiteLLM exposes an OpenAI-compatible API and fronts the real providers
// (Bedrock, Vertex, etc.) with their credentials held on the proxy, so this
// reuses the langchaingo OpenAI client pointed at the proxy. apiKey is the
// LiteLLM virtual key and baseURL is the proxy endpoint (both required). The
// adapter is named "litellm" so analytics distinguish it from direct OpenAI.
// The model id is the proxy's configured alias (e.g. claude-sonnet-4-6), supplied
// per request via llms.WithModel, the same as the other langchaingo adapters.
func NewLiteLLMAdapter(apiKey, baseURL string, extra http.Header, base http.RoundTripper) (*LangchainAdapter, error) {
	if baseURL == "" {
		return nil, errors.New("litellm: LITELLM_BASE_URL is required")
	}
	normalized, err := normalizeOpenAIBaseURL(baseURL)
	if err != nil {
		return nil, fmt.Errorf("litellm: %w", err)
	}
	oo := []openai.Option{openai.WithToken(tokenOrPlaceholder(apiKey)), openai.WithBaseURL(normalized)}
	var strip []string
	if apiKey == "" {
		strip = openAIAuthHeaders
	}
	if c := headerClient(baseOrDefault(base), extra, strip, strippedBodyFields); c != nil {
		oo = append(oo, openai.WithHTTPClient(c))
	}
	llm, err := openai.New(oo...)
	if err != nil {
		return nil, err
	}
	a := NewLangchainAdapter("litellm", llm)
	a.splitToolResults = true // LiteLLM speaks OpenAI: one part per tool message
	return a, nil
}

// normalizeOpenAIBaseURL makes a user-supplied OpenAI-compatible base URL
// robust. langchaingo posts to "<base>/chat/completions" and does NOT add the
// "/v1" segment itself, so a bare host (e.g. https://proxy) would hit
// "<host>/chat/completions" and 404 on proxies (LiteLLM included) that serve
// the OpenAI API under /v1. We therefore:
//   - reject non-HTTPS to prevent sending the API key and source code in
//     plaintext (localhost is allowed for local development)
//   - trim a trailing "/" and an accidentally-pasted "/chat/completions" suffix
//   - append "/v1" when the URL has no path, matching the OpenAI convention
//     (https://api.openai.com/v1)
//
// An explicit path (an existing "/v1", or a custom gateway prefix) is left
// untouched, so users who know their proxy's layout can override the default.
func normalizeOpenAIBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://localhost") && !strings.HasPrefix(lower, "http://127.0.0.1") {
		return "", fmt.Errorf("LITELLM_BASE_URL must use HTTPS (got %q); plain HTTP would send your API key and source code in cleartext", raw)
	}
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, "/chat/completions")
	s = strings.TrimRight(s, "/")
	if u, err := url.Parse(s); err == nil && u.Path == "" {
		s += "/v1"
	}
	return s, nil
}

// normalizeAnthropicBaseURL makes a user-supplied Anthropic-compatible base URL
// robust. langchaingo posts to "<base>/messages" without adding "/v1", so a bare
// host (https://proxy) would hit "<host>/messages" and 404 on a proxy that
// serves the API under /v1. We trim a trailing "/" and an accidentally-pasted
// "/messages" suffix, then append "/v1" when the URL has no path. An explicit
// path (an existing "/v1" or a custom gateway prefix) is left untouched. Unlike
// the OpenAI helper this does not enforce HTTPS: the keyless gateway case (no
// API key to leak) commonly runs over plain HTTP on an internal host.
func normalizeAnthropicBaseURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, "/messages")
	s = strings.TrimRight(s, "/")
	if u, err := url.Parse(s); err == nil && u.Path == "" {
		s += "/v1"
	}
	return s
}

// NewOllamaAdapter builds a LangchainAdapter backed by an in-package Ollama
// llms.Model implementation (see ollama_model.go) — langchaingo's bundled
// Ollama provider does not forward tools or extract tool calls, so we hit
// /api/chat directly while keeping the same llms.Model interface. model is
// required; baseURL defaults to http://localhost:11434 when empty. base is the
// shared HTTP transport (nil = default).
func NewOllamaAdapter(model, baseURL string, base http.RoundTripper) (*LangchainAdapter, error) {
	if model == "" {
		return nil, errors.New("ollama: model is required (set --model)")
	}
	if baseURL == "" {
		baseURL = defaultOllamaHost
	}
	return NewLangchainAdapter("ollama", newOllamaChatModel(model, baseURL, base)), nil
}

// NewVertexAdapter builds a LangchainAdapter backed by an in-package Vertex AI
// llms.Model (see vertex_model.go) that drives Google's google.golang.org/genai
// SDK against the Vertex backend. project and location are the GCP project ID
// and region; auth is Application Default Credentials (no API key). model is
// the default model id (a full Model Garden path, e.g.
// publishers/google/models/gemini-2.5-flash) used when a call doesn't override
// it with --model. baseURL is optional — empty means use Vertex's default
// endpoint; set it to route through a regional endpoint or a proxy. authToken is
// optional — when set, the adapter authenticates with that bearer token instead
// of Google ADC (for a gateway that expects "Authorization: Bearer <token>").
// extra carries additional headers added to every request (gateway headers).
// base is the shared HTTP transport for the bearer path (nil = default).
func NewVertexAdapter(model, project, location, baseURL, authToken string, extra http.Header, base http.RoundTripper) (*LangchainAdapter, error) {
	m, err := newVertexModel(context.Background(), model, project, location, baseURL, authToken, extra, base)
	if err != nil {
		return nil, err
	}
	return NewLangchainAdapter("vertex", m), nil
}
