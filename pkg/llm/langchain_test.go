package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmc/langchaingo/llms"

	"github.com/snyk/go-application-framework/pkg/llm"
)

// fakeLLM is an in-package llms.Model that records the last GenerateContent
// call and returns a scripted response. No HTTP, no network — pure mapping
// test double for LangchainAdapter.
type fakeLLM struct {
	gotMessages []llms.MessageContent
	gotOptions  *llms.CallOptions
	resp        *llms.ContentResponse
	err         error
}

func (f *fakeLLM) GenerateContent(_ context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	f.gotMessages = msgs
	co := &llms.CallOptions{}
	for _, o := range opts {
		o(co)
	}
	f.gotOptions = co
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeLLM) Call(_ context.Context, _ string, _ ...llms.CallOption) (string, error) {
	return "", nil
}

// emptyResp keeps the adapter happy when a test only cares about the input
// side of the mapping.
func emptyResp() *llms.ContentResponse {
	return &llms.ContentResponse{
		Choices: []*llms.ContentChoice{{StopReason: "stop"}},
	}
}

// Test 1 — system prompt + user message are forwarded as the expected
// MessageContent slice.
func TestLangchainAdapter_ForwardsSystemAndUserMessage(t *testing.T) {
	model := &fakeLLM{resp: emptyResp()}
	a := llm.NewLangchainAdapter("anthropic", model)

	_, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		SystemPrompt: "you are a fixer",
		Model:        "claude-sonnet-4-6",
		MaxTokens:    1024,
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "scan this repo"},
		},
	})
	require.NoError(t, err)

	require.Len(t, model.gotMessages, 2)
	assert.Equal(t, llms.ChatMessageTypeSystem, model.gotMessages[0].Role)
	require.Len(t, model.gotMessages[0].Parts, 1)
	assert.Equal(t, llms.TextContent{Text: "you are a fixer"}, model.gotMessages[0].Parts[0])

	assert.Equal(t, llms.ChatMessageTypeHuman, model.gotMessages[1].Role)
	require.Len(t, model.gotMessages[1].Parts, 1)
	assert.Equal(t, llms.TextContent{Text: "scan this repo"}, model.gotMessages[1].Parts[0])
}

// Test 2 — an assistant tool-call followed by a tool-result roundtrip maps to
// the right Parts in the right order with matching ToolCallID.
func TestLangchainAdapter_AssistantToolCallRoundtripParts(t *testing.T) {
	model := &fakeLLM{resp: emptyResp()}
	a := llm.NewLangchainAdapter("openai", model)

	_, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		MaxTokens: 1024,
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "scan"},
			{
				Role:    llm.RoleAssistant,
				Content: "running tool",
				ToolCalls: []llm.ToolCall{
					{ID: "call_1", Name: "snyk_scan", Input: json.RawMessage(`{"path":"."}`)},
				},
			},
			{
				Role: llm.RoleUser,
				ToolResults: []llm.ToolResult{
					{ToolCallID: "call_1", Content: "no issues"},
				},
			},
		},
	})
	require.NoError(t, err)

	require.Len(t, model.gotMessages, 3)

	// Assistant message has text part + tool-call part with matching ID.
	assistant := model.gotMessages[1]
	assert.Equal(t, llms.ChatMessageTypeAI, assistant.Role)
	require.Len(t, assistant.Parts, 2)
	assert.Equal(t, llms.TextContent{Text: "running tool"}, assistant.Parts[0])
	tc, ok := assistant.Parts[1].(llms.ToolCall)
	require.True(t, ok, "second part of assistant message must be ToolCall, got %T", assistant.Parts[1])
	assert.Equal(t, "call_1", tc.ID)
	assert.Equal(t, "function", tc.Type)
	require.NotNil(t, tc.FunctionCall)
	assert.Equal(t, "snyk_scan", tc.FunctionCall.Name)
	assert.JSONEq(t, `{"path":"."}`, tc.FunctionCall.Arguments)

	// Tool-result message has Role=Tool and a ToolCallResponse part with the
	// same call ID.
	toolMsg := model.gotMessages[2]
	assert.Equal(t, llms.ChatMessageTypeTool, toolMsg.Role)
	require.Len(t, toolMsg.Parts, 1)
	tr, ok := toolMsg.Parts[0].(llms.ToolCallResponse)
	require.True(t, ok, "tool message part must be ToolCallResponse, got %T", toolMsg.Parts[0])
	assert.Equal(t, "call_1", tr.ToolCallID)
	assert.Equal(t, "no issues", tr.Content)
}

// Test 3 — tool definitions are forwarded as llms.Tool with parsed parameters.
func TestLangchainAdapter_ForwardsToolDefinitions(t *testing.T) {
	model := &fakeLLM{resp: emptyResp()}
	a := llm.NewLangchainAdapter("anthropic", model)

	schema := json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`)
	_, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		MaxTokens: 1024,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "go"}},
		Tools: []llm.ToolDefinition{
			{Name: "snyk_scan", Description: "Run a Snyk SCA scan", InputSchema: schema},
		},
	})
	require.NoError(t, err)

	require.NotNil(t, model.gotOptions)
	require.Len(t, model.gotOptions.Tools, 1)
	tool := model.gotOptions.Tools[0]
	assert.Equal(t, "function", tool.Type)
	require.NotNil(t, tool.Function)
	assert.Equal(t, "snyk_scan", tool.Function.Name)
	assert.Equal(t, "Run a Snyk SCA scan", tool.Function.Description)

	// Parameters should be the parsed JSON Schema, not the raw bytes.
	params, ok := tool.Function.Parameters.(map[string]any)
	require.True(t, ok, "Parameters must be parsed map, got %T", tool.Function.Parameters)
	assert.Equal(t, "object", params["type"])
}

// Test 4 — text content from Choices[0] flows into ChatResponse.Content.
func TestLangchainAdapter_ReturnsTextContent(t *testing.T) {
	model := &fakeLLM{resp: &llms.ContentResponse{
		Choices: []*llms.ContentChoice{
			{Content: "fix complete", StopReason: "stop"},
		},
	}}
	a := llm.NewLangchainAdapter("openai", model)

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "go"}},
		MaxTokens: 100,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "fix complete", resp.Content)
	assert.Empty(t, resp.ToolCalls)
	assert.Equal(t, llm.StopEndTurn, resp.StopReason)
}

// Test 5 — tool calls in the response are extracted with ID/Name/Input.
func TestLangchainAdapter_ExtractsToolCalls(t *testing.T) {
	model := &fakeLLM{resp: &llms.ContentResponse{
		Choices: []*llms.ContentChoice{
			{
				StopReason: "tool_calls",
				ToolCalls: []llms.ToolCall{
					{
						ID:           "call_42",
						Type:         "function",
						FunctionCall: &llms.FunctionCall{Name: "snyk_scan", Arguments: `{"path":"./api"}`},
					},
				},
			},
		},
	}}
	a := llm.NewLangchainAdapter("openai", model)

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "go"}},
		MaxTokens: 100,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "call_42", resp.ToolCalls[0].ID)
	assert.Equal(t, "snyk_scan", resp.ToolCalls[0].Name)
	assert.JSONEq(t, `{"path":"./api"}`, string(resp.ToolCalls[0].Input))
}

// Test 6 — stop-reason normalization covers Anthropic and OpenAI literals
// (langchain providers pass the upstream string through unchanged).
func TestLangchainAdapter_NormalizesStopReasons(t *testing.T) {
	cases := []struct {
		raw  string
		want llm.StopReason
	}{
		{"tool_calls", llm.StopToolUse},   // openai
		{"tool_use", llm.StopToolUse},     // anthropic
		{"length", llm.StopMaxTokens},     // openai
		{"max_tokens", llm.StopMaxTokens}, // anthropic
		{"stop", llm.StopEndTurn},         // openai
		{"end_turn", llm.StopEndTurn},     // anthropic
		{"", llm.StopEndTurn},
		{"who-knows", llm.StopEndTurn},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			model := &fakeLLM{resp: &llms.ContentResponse{
				Choices: []*llms.ContentChoice{{StopReason: tc.raw}},
			}}
			a := llm.NewLangchainAdapter("x", model)
			resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
				Messages:  []llm.Message{{Role: llm.RoleUser, Content: "."}},
				MaxTokens: 1,
			})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tc.want, resp.StopReason)
		})
	}
}

// Test 7 — TokenUsage reads from GenerationInfo. Anthropic uses
// InputTokens/OutputTokens, OpenAI/Ollama use PromptTokens/CompletionTokens.
// Missing keys default to 0.
func TestLangchainAdapter_TokenUsageFromGenerationInfo(t *testing.T) {
	t.Run("openai/ollama keys", func(t *testing.T) {
		model := &fakeLLM{resp: &llms.ContentResponse{
			Choices: []*llms.ContentChoice{{
				StopReason:     "stop",
				GenerationInfo: map[string]any{"PromptTokens": 42, "CompletionTokens": 7},
			}},
		}}
		a := llm.NewLangchainAdapter("openai", model)
		resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
			Messages: []llm.Message{{Role: llm.RoleUser, Content: "."}}, MaxTokens: 1,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 42, resp.Usage.Input)
		assert.Equal(t, 7, resp.Usage.Output)
	})

	t.Run("anthropic keys", func(t *testing.T) {
		model := &fakeLLM{resp: &llms.ContentResponse{
			Choices: []*llms.ContentChoice{{
				StopReason:     "end_turn",
				GenerationInfo: map[string]any{"InputTokens": 100, "OutputTokens": 25},
			}},
		}}
		a := llm.NewLangchainAdapter("anthropic", model)
		resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
			Messages: []llm.Message{{Role: llm.RoleUser, Content: "."}}, MaxTokens: 1,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 100, resp.Usage.Input)
		assert.Equal(t, 25, resp.Usage.Output)
	})

	t.Run("missing keys default to zero", func(t *testing.T) {
		model := &fakeLLM{resp: &llms.ContentResponse{
			Choices: []*llms.ContentChoice{{StopReason: "stop"}},
		}}
		a := llm.NewLangchainAdapter("openai", model)
		resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
			Messages: []llm.Message{{Role: llm.RoleUser, Content: "."}}, MaxTokens: 1,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 0, resp.Usage.Input)
		assert.Equal(t, 0, resp.Usage.Output)
	})
}

// Test 8 — Name() returns the id passed to the constructor.
func TestLangchainAdapter_Name(t *testing.T) {
	for _, name := range []string{"anthropic", "openai", "ollama"} {
		assert.Equal(t, name, llm.NewLangchainAdapter(name, &fakeLLM{}).Name())
	}
}

// Test 9 — adapter propagates a non-nil error from the underlying llms.Model.
func TestLangchainAdapter_PropagatesError(t *testing.T) {
	boom := errors.New("model unavailable")
	model := &fakeLLM{err: boom}
	a := llm.NewLangchainAdapter("openai", model)

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "."}},
		MaxTokens: 1,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, boom)
}

// Bonus — Anthropic-style responses split text and tool_use across separate
// Choices (one ContentChoice per content block). The adapter must aggregate
// them into a single ChatResponse.
func TestLangchainAdapter_AggregatesMultipleChoices(t *testing.T) {
	model := &fakeLLM{resp: &llms.ContentResponse{
		Choices: []*llms.ContentChoice{
			{Content: "let me check", StopReason: "tool_use"},
			{
				StopReason: "tool_use",
				ToolCalls: []llms.ToolCall{
					{ID: "t1", FunctionCall: &llms.FunctionCall{Name: "snyk_scan", Arguments: `{}`}},
				},
			},
		},
	}}
	a := llm.NewLangchainAdapter("anthropic", model)

	resp, err := a.ChatCompletion(ctx(), &llm.ChatRequest{
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "."}},
		MaxTokens: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "let me check", resp.Content)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "t1", resp.ToolCalls[0].ID)
	assert.Equal(t, llm.StopToolUse, resp.StopReason)
}
