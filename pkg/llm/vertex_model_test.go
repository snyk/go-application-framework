package llm

import (
	"encoding/json"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmc/langchaingo/llms"
	"google.golang.org/genai"
)

// --- publisher routing -------------------------------------------------------

func TestIsAnthropicModel(t *testing.T) {
	cases := []struct {
		model string
		want  bool
	}{
		{"claude-sonnet-4-6", true},
		{"claude-opus-4-8@20250101", true},
		{"publishers/anthropic/models/claude-sonnet-4-6", true},
		{"gemini-2.5-flash", false},
		{"publishers/google/models/gemini-2.5-flash", false},
		{"", false},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, isAnthropicModel(tc.model), "model=%q", tc.model)
	}
}

func TestAnthropicModelID(t *testing.T) {
	// Full path is stripped to the bare id; bare ids (with or without an
	// @version suffix) pass through unchanged.
	assert.Equal(t, "claude-sonnet-4-6", anthropicModelID("publishers/anthropic/models/claude-sonnet-4-6"))
	assert.Equal(t, "claude-sonnet-4-6@20250101", anthropicModelID("publishers/anthropic/models/claude-sonnet-4-6@20250101"))
	assert.Equal(t, "claude-sonnet-4-6", anthropicModelID("claude-sonnet-4-6"))
}

// --- message mapping ---------------------------------------------------------

func TestLCToAnthropicMessages(t *testing.T) {
	in := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextContent{Text: "be helpful"}}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextContent{Text: "hi there"}}},
		{Role: llms.ChatMessageTypeAI, Parts: []llms.ContentPart{
			llms.TextContent{Text: "thinking"},
			llms.ToolCall{ID: "call1", FunctionCall: &llms.FunctionCall{Name: "get_x", Arguments: `{"a":1}`}},
		}},
		{Role: llms.ChatMessageTypeTool, Parts: []llms.ContentPart{
			llms.ToolCallResponse{ToolCallID: "call1", Content: "result"},
		}},
	}

	msgs, system := lcToAnthropicMessages(in)

	// System is returned separately, not as a message.
	require.Len(t, system, 1)
	assert.Equal(t, "be helpful", system[0].Text)

	require.Len(t, msgs, 3, "human + assistant + tool-result user")

	// Human → user with one text block.
	assert.Equal(t, "user", string(msgs[0].Role))
	require.Len(t, msgs[0].Content, 1)
	require.NotNil(t, msgs[0].Content[0].OfText)
	assert.Equal(t, "hi there", msgs[0].Content[0].OfText.Text)

	// Assistant → text block + tool_use block.
	assert.Equal(t, "assistant", string(msgs[1].Role))
	require.Len(t, msgs[1].Content, 2)
	require.NotNil(t, msgs[1].Content[0].OfText)
	assert.Equal(t, "thinking", msgs[1].Content[0].OfText.Text)
	require.NotNil(t, msgs[1].Content[1].OfToolUse)
	assert.Equal(t, "call1", msgs[1].Content[1].OfToolUse.ID)
	assert.Equal(t, "get_x", msgs[1].Content[1].OfToolUse.Name)

	// Tool result → user message with a tool_result block carrying the id.
	assert.Equal(t, "user", string(msgs[2].Role))
	require.Len(t, msgs[2].Content, 1)
	require.NotNil(t, msgs[2].Content[0].OfToolResult)
	assert.Equal(t, "call1", msgs[2].Content[0].OfToolResult.ToolUseID)
}

func TestLCToAnthropicMessages_EmptyTextDropped(t *testing.T) {
	// An assistant turn with only an empty text part produces no message.
	in := []llms.MessageContent{
		{Role: llms.ChatMessageTypeAI, Parts: []llms.ContentPart{llms.TextContent{Text: ""}}},
	}
	msgs, system := lcToAnthropicMessages(in)
	assert.Empty(t, msgs)
	assert.Empty(t, system)
}

// --- tool mapping ------------------------------------------------------------

func TestLCToAnthropicTools(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"location": map[string]any{"type": "string"},
		},
		"required": []any{"location"},
	}
	tools := []llms.Tool{
		{Function: &llms.FunctionDefinition{Name: "get_weather", Description: "gets weather", Parameters: schema}},
	}

	out := lcToAnthropicTools(tools)
	require.Len(t, out, 1)
	require.NotNil(t, out[0].OfTool)
	assert.Equal(t, "get_weather", out[0].OfTool.Name)
	assert.Equal(t, "gets weather", out[0].OfTool.Description.Value)
	assert.NotNil(t, out[0].OfTool.InputSchema.Properties)
	assert.Equal(t, []string{"location"}, out[0].OfTool.InputSchema.Required)
}

func TestLCToAnthropicTools_EmptyAndNilFunction(t *testing.T) {
	assert.Nil(t, lcToAnthropicTools(nil))
	assert.Nil(t, lcToAnthropicTools([]llms.Tool{{Function: nil}}), "a tool with no function is skipped")
}

// --- response mapping --------------------------------------------------------

func TestAnthropicToLCResponse(t *testing.T) {
	// Build the Message by unmarshaling a realistic Messages API response: the
	// SDK's content-block unions resolve their typed variant (AsAny) from the
	// stored raw JSON, so hand-built struct literals would come back empty.
	const raw = `{
		"id": "msg_1",
		"type": "message",
		"role": "assistant",
		"model": "claude-sonnet-4-6",
		"content": [
			{"type": "text", "text": "here you go"},
			{"type": "tool_use", "id": "tu1", "name": "get_x", "input": {"a": 1}}
		],
		"stop_reason": "tool_use",
		"usage": {"input_tokens": 12, "output_tokens": 34}
	}`
	var msg anthropic.Message
	require.NoError(t, json.Unmarshal([]byte(raw), &msg))

	resp := anthropicToLCResponse(&msg)
	require.Len(t, resp.Choices, 1)
	c := resp.Choices[0]

	assert.Equal(t, "here you go", c.Content)
	require.Len(t, c.ToolCalls, 1)
	assert.Equal(t, "tu1", c.ToolCalls[0].ID)
	assert.Equal(t, "get_x", c.ToolCalls[0].FunctionCall.Name)
	assert.JSONEq(t, `{"a":1}`, c.ToolCalls[0].FunctionCall.Arguments)

	// Stop reason is a string normalizeStopReason already understands.
	assert.Equal(t, "tool_use", c.StopReason)
	assert.Equal(t, StopToolUse, normalizeStopReason(c.StopReason))

	assert.Equal(t, 12, c.GenerationInfo["InputTokens"])
	assert.Equal(t, 34, c.GenerationInfo["OutputTokens"])
}

func TestAnthropicToLCResponse_Nil(t *testing.T) {
	resp := anthropicToLCResponse(nil)
	require.Len(t, resp.Choices, 1)
	assert.Empty(t, resp.Choices[0].Content)
	assert.Empty(t, resp.Choices[0].ToolCalls)
}

// Both Gemini and Claude on Vertex must produce GenerationInfo keys that
// readTokenUsage recognises. Before this fix, genaiToLCResponse used
// "PromptTokens"/"CompletionTokens" while anthropicToLCResponse used
// "InputTokens"/"OutputTokens" — both must now use the same keys.
func TestTokenUsageKeysConsistent(t *testing.T) {
	// Gemini path: genaiToLCResponse
	geminiResp := genaiToLCResponse(&genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{Content: &genai.Content{Parts: []*genai.Part{{Text: "hi"}}}},
		},
		UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
			PromptTokenCount:     10,
			CandidatesTokenCount: 20,
		},
	})
	require.Len(t, geminiResp.Choices, 1)
	geminiUsage := readTokenUsage(geminiResp.Choices[0].GenerationInfo)
	assert.Equal(t, 10, geminiUsage.Input, "Gemini: InputTokens must be populated")
	assert.Equal(t, 20, geminiUsage.Output, "Gemini: OutputTokens must be populated")

	// Claude path: anthropicToLCResponse (keys already use InputTokens/OutputTokens)
	const raw = `{
		"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-6",
		"content":[{"type":"text","text":"hi"}],
		"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":15}
	}`
	var msg anthropic.Message
	require.NoError(t, json.Unmarshal([]byte(raw), &msg))
	claudeResp := anthropicToLCResponse(&msg)
	require.Len(t, claudeResp.Choices, 1)
	claudeUsage := readTokenUsage(claudeResp.Choices[0].GenerationInfo)
	assert.Equal(t, 5, claudeUsage.Input, "Claude-on-Vertex: InputTokens must be populated")
	assert.Equal(t, 15, claudeUsage.Output, "Claude-on-Vertex: OutputTokens must be populated")
}
