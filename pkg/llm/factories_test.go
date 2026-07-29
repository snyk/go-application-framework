package llm_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/llm"
)

// Anthropic /v1/messages mock — minimal SSE response with one tool_use block.
// The langchaingo Anthropic provider uses non-streaming /v1/messages by
// default (no stream:true unless configured), so we serve plain JSON.
func anthropicToolUseHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		// srv.URL is a bare host, so normalizeAnthropicBaseURL appends /v1 and
		// langchaingo then posts to /v1/messages.
		assert.Equal(t, "/v1/messages", r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		// Tool definition must be forwarded.
		assert.Contains(t, string(body), `"name":"snyk_scan"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "msg_1",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-6",
			"stop_reason": "tool_use",
			"content": [
				{"type": "text", "text": "running scan"},
				{"type": "tool_use", "id": "toolu_abc", "name": "snyk_scan", "input": {"path": "."}}
			],
			"usage": {"input_tokens": 12, "output_tokens": 8}
		}`))
	}
}

// Test 10 — Anthropic factory against an httptest /v1/messages server.
func TestNewAnthropicAdapter_ToolCallRoundtrip(t *testing.T) {
	srv := httptest.NewServer(anthropicToolUseHandler(t))
	defer srv.Close()

	a, err := llm.NewAnthropicAdapter("test-key", srv.URL, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "anthropic", a.Name())

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 1024,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "scan"}},
		Tools: []llm.ToolDefinition{
			{Name: "snyk_scan", Description: "scan", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, llm.StopToolUse, resp.StopReason)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "toolu_abc", resp.ToolCalls[0].ID)
	assert.Equal(t, "snyk_scan", resp.ToolCalls[0].Name)
}

// The adapter must strip langchaingo's hardcoded temperature:0 from the request
// body — current models reject the parameter ("temperature is deprecated for
// this model"). Without the strip, langchaingo would serialize "temperature":0
// (its wire struct has no omitempty) and this assertion would fail.
func TestNewAnthropicAdapter_StripsTemperature(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","type":"message","role":"assistant","model":"m","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	a, err := llm.NewAnthropicAdapter("test-key", srv.URL, nil, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 1024,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
	})
	require.NoError(t, err)
	assert.NotContains(t, gotBody, `"temperature"`, "temperature must be stripped from the request body")
}

// A missing API key must not fail construction: langchaingo requires a
// non-empty token, so the factory substitutes a placeholder and defers any real
// auth failure to call time (a base-URL gateway may inject auth instead).
func TestNewAnthropicAdapter_NoKeyStillConstructs(t *testing.T) {
	a, err := llm.NewAnthropicAdapter("", "https://gateway.example.com", nil, nil)
	require.NoError(t, err, "missing key must not fail at construction")
	require.NotNil(t, a)
	assert.Equal(t, "anthropic", a.Name())
}

// anthropicCaptureKeyHandler records the x-api-key header the client sent and
// returns a minimal valid message so the round-trip completes.
func anthropicCaptureKeyHandler(got *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-4-6","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}
}

func anthropicProbeRequest() *llm.ChatRequest {
	return &llm.ChatRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 16,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
	}
}

// Caller-supplied extra headers (e.g. a gateway identity header) must be sent
// on the wire, alongside the real key.
func TestNewAnthropicAdapter_SendsExtraHeaders(t *testing.T) {
	var gotUser, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("x-user-id")
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-4-6","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	a, err := llm.NewAnthropicAdapter("real-key-123", srv.URL, http.Header{"x-user-id": {"jsmith"}}, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), anthropicProbeRequest())
	require.NoError(t, err)
	assert.Equal(t, "jsmith", gotUser, "extra gateway headers must be sent")
	// Installing the header transport must not drop langchaingo's User-Agent.
	assert.Contains(t, gotUA, "langchaingo", "langchaingo User-Agent must be preserved")
}

// With no key set, the placeholder must be stripped on the wire so a base-URL
// gateway sees no x-api-key and applies its own auth.
func TestNewAnthropicAdapter_NoKeyStripsAPIKeyHeader(t *testing.T) {
	var sentKey string
	srv := httptest.NewServer(anthropicCaptureKeyHandler(&sentKey))
	defer srv.Close()

	a, err := llm.NewAnthropicAdapter("", srv.URL, nil, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), anthropicProbeRequest())
	require.NoError(t, err)
	assert.Empty(t, sentKey, "x-api-key must not be sent when no key is configured")
}

// With a key set, it must reach the endpoint unchanged (gateways that pass auth
// through still work).
func TestNewAnthropicAdapter_KeyReachesEndpoint(t *testing.T) {
	var sentKey string
	srv := httptest.NewServer(anthropicCaptureKeyHandler(&sentKey))
	defer srv.Close()

	a, err := llm.NewAnthropicAdapter("real-key-123", srv.URL, nil, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), anthropicProbeRequest())
	require.NoError(t, err)
	assert.Equal(t, "real-key-123", sentKey, "a configured key must reach the endpoint")
}

func TestNewOpenAIAdapter_NoKeyStillConstructs(t *testing.T) {
	a, err := llm.NewOpenAIAdapter("", "", nil, nil)
	require.NoError(t, err, "missing key must not fail at construction")
	require.NotNil(t, a)
	assert.Equal(t, "openai", a.Name())
}

// openAICaptureAuthHandler records the Authorization header and returns a
// minimal valid chat completion so the round-trip succeeds.
func openAICaptureAuthHandler(got *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}
}

func openAIProbeRequest() *llm.ChatRequest {
	return &llm.ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: 16,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
	}
}

// No key → the Authorization header must be stripped on the wire so an
// OpenAI-compatible gateway (e.g. a proxy) applies its own auth.
func TestNewOpenAIAdapter_NoKeyStripsAuthHeader(t *testing.T) {
	var sentAuth string
	srv := httptest.NewServer(openAICaptureAuthHandler(&sentAuth))
	defer srv.Close()

	a, err := llm.NewOpenAIAdapter("", srv.URL, nil, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), openAIProbeRequest())
	require.NoError(t, err)
	assert.Empty(t, sentAuth, "Authorization must not be sent when no key is configured")
}

// The OpenAI/LiteLLM path shares the headerTransport seam; assert extra headers
// reach the wire there too.
func TestNewOpenAIAdapter_SendsExtraHeaders(t *testing.T) {
	var gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("x-user-id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer srv.Close()

	a, err := llm.NewOpenAIAdapter("real-key-123", srv.URL, http.Header{"x-user-id": {"jsmith"}}, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), openAIProbeRequest())
	require.NoError(t, err)
	assert.Equal(t, "jsmith", gotUser, "extra gateway headers must be sent")
}

func TestNewOpenAIAdapter_KeyReachesEndpoint(t *testing.T) {
	var sentAuth string
	srv := httptest.NewServer(openAICaptureAuthHandler(&sentAuth))
	defer srv.Close()

	a, err := llm.NewOpenAIAdapter("real-key-123", srv.URL, nil, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), openAIProbeRequest())
	require.NoError(t, err)
	assert.Equal(t, "Bearer real-key-123", sentAuth, "a configured key must reach the endpoint")
}

// OpenAI /v1/chat/completions mock — text + tool call response.
func openAIToolCallHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		// langchaingo's OpenAI provider appends its own API version.
		assert.Equal(t, "/chat/completions", r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		assert.Contains(t, string(body), `"name":"snyk_scan"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl-1",
			"object": "chat.completion",
			"model": "gpt-4o",
			"choices": [{
				"index": 0,
				"finish_reason": "tool_calls",
				"message": {
					"role": "assistant",
					"content": null,
					"tool_calls": [{
						"id": "call_xyz",
						"type": "function",
						"function": {"name": "snyk_scan", "arguments": "{\"path\":\".\"}"}
					}]
				}
			}],
			"usage": {"prompt_tokens": 22, "completion_tokens": 9, "total_tokens": 31}
		}`))
	}
}

// Test 11 — OpenAI factory against an httptest /v1/chat/completions server.
func TestNewOpenAIAdapter_ToolCallRoundtrip(t *testing.T) {
	srv := httptest.NewServer(openAIToolCallHandler(t))
	defer srv.Close()

	a, err := llm.NewOpenAIAdapter("test-key", srv.URL, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "openai", a.Name())

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: 1024,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "scan"}},
		Tools: []llm.ToolDefinition{
			{Name: "snyk_scan", Description: "scan", InputSchema: json.RawMessage(`{"type":"object"}`)},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, llm.StopToolUse, resp.StopReason)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "call_xyz", resp.ToolCalls[0].ID)
	assert.Equal(t, "snyk_scan", resp.ToolCalls[0].Name)
	assert.Equal(t, 22, resp.Usage.Input)
	assert.Equal(t, 9, resp.Usage.Output)
}

// Ollama /api/chat mock — non-streaming response with a tool call.
// Ollama 0.3+ supports the "tools" parameter and returns "tool_calls" on the
// message. We assert the request payload includes the tool definition.
func ollamaChatHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/chat", r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		var got map[string]any
		require.NoError(t, json.Unmarshal(body, &got))
		assert.Equal(t, "llama3.1", got["model"])
		assert.Equal(t, false, got["stream"])
		tools, ok := got["tools"].([]any)
		require.True(t, ok, "expected tools[] in payload")
		require.Len(t, tools, 1)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model": "llama3.1",
			"created_at": "2026-05-21T12:00:00Z",
			"done": true,
			"done_reason": "stop",
			"message": {
				"role": "assistant",
				"content": "",
				"tool_calls": [{
					"function": {"name": "snyk_scan", "arguments": {"path": "."}}
				}]
			},
			"prompt_eval_count": 18,
			"eval_count": 4
		}`))
	}
}

// Test 12 — Ollama factory against an httptest /api/chat server.
func TestNewOllamaAdapter_ToolCallRoundtrip(t *testing.T) {
	srv := httptest.NewServer(ollamaChatHandler(t))
	defer srv.Close()

	a, err := llm.NewOllamaAdapter("llama3.1", srv.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "ollama", a.Name())

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "llama3.1",
		MaxTokens: 256,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "scan"}},
		Tools: []llm.ToolDefinition{
			{Name: "snyk_scan", Description: "scan", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, llm.StopToolUse, resp.StopReason)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "snyk_scan", resp.ToolCalls[0].Name)
	assert.JSONEq(t, `{"path":"."}`, string(resp.ToolCalls[0].Input))
	assert.Equal(t, 18, resp.Usage.Input)
	assert.Equal(t, 4, resp.Usage.Output)
}

// Test 12b — Ollama text-only path (no tools, no tool_calls in response).
func TestNewOllamaAdapter_TextOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/chat", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model": "llama3.1",
			"done": true,
			"done_reason": "stop",
			"message": {"role": "assistant", "content": "hello back"},
			"prompt_eval_count": 5,
			"eval_count": 2
		}`))
	}))
	defer srv.Close()

	a, err := llm.NewOllamaAdapter("llama3.1", srv.URL, nil)
	require.NoError(t, err)

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "llama3.1",
		MaxTokens: 50,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "hello back", resp.Content)
	assert.Empty(t, resp.ToolCalls)
	assert.Equal(t, llm.StopEndTurn, resp.StopReason)
}

// Test 13 — each factory propagates a 4xx from the server as a non-nil error.
func TestFactories_4xxError(t *testing.T) {
	make4xx := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad key"}`))
		}))
	}

	t.Run("anthropic", func(t *testing.T) {
		srv := make4xx()
		defer srv.Close()
		a, err := llm.NewAnthropicAdapter("bad", srv.URL, nil, nil)
		require.NoError(t, err)
		_, callErr := a.ChatCompletion(ctx(), &llm.ChatRequest{
			Model: "claude-sonnet-4-6", MaxTokens: 10,
			Messages: []llm.Message{{Role: llm.RoleUser, Content: "x"}},
		})
		assert.Error(t, callErr)
	})

	t.Run("openai", func(t *testing.T) {
		srv := make4xx()
		defer srv.Close()
		a, err := llm.NewOpenAIAdapter("bad", srv.URL, nil, nil)
		require.NoError(t, err)
		_, callErr := a.ChatCompletion(ctx(), &llm.ChatRequest{
			Model: "gpt-4o", MaxTokens: 10,
			Messages: []llm.Message{{Role: llm.RoleUser, Content: "x"}},
		})
		assert.Error(t, callErr)
	})

	t.Run("ollama", func(t *testing.T) {
		srv := make4xx()
		defer srv.Close()
		a, err := llm.NewOllamaAdapter("llama3.1", srv.URL, nil)
		require.NoError(t, err)
		_, callErr := a.ChatCompletion(ctx(), &llm.ChatRequest{
			Model: "llama3.1", MaxTokens: 10,
			Messages: []llm.Message{{Role: llm.RoleUser, Content: "x"}},
		})
		assert.Error(t, callErr)
	})
}

// Test 13b — NewOllamaAdapter rejects an empty model up-front.
func TestNewOllamaAdapter_RequiresModel(t *testing.T) {
	a, err := llm.NewOllamaAdapter("", "http://localhost:11434", nil)
	assert.Nil(t, a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

// NewLiteLLMAdapter reuses the OpenAI-compatible client (LiteLLM proxy) but
// names the adapter "litellm" so analytics distinguish it from direct OpenAI.
func TestNewLiteLLMAdapter_Name(t *testing.T) {
	a, err := llm.NewLiteLLMAdapter("sk-litellm-...", "https://litellm.example.com", nil, nil)
	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Equal(t, "litellm", a.Name())
}

// NewLiteLLMAdapter rejects an empty base URL up-front — there is no sensible
// default for the LiteLLM proxy endpoint.
func TestNewLiteLLMAdapter_RequiresBaseURL(t *testing.T) {
	a, err := llm.NewLiteLLMAdapter("sk-litellm-...", "", nil, nil)
	assert.Nil(t, a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LITELLM_BASE_URL")
}
