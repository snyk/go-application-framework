package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmc/langchaingo/llms"
)

func TestSplitToolResultMessages(t *testing.T) {
	// A tool turn with two results (parallel tool calls) must become two
	// single-part tool messages, in order; everything else is untouched.
	in := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextContent{Text: "sys"}}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextContent{Text: "hi"}}},
		{Role: llms.ChatMessageTypeAI, Parts: []llms.ContentPart{
			llms.ToolCall{ID: "a", FunctionCall: &llms.FunctionCall{Name: "f", Arguments: "{}"}},
			llms.ToolCall{ID: "b", FunctionCall: &llms.FunctionCall{Name: "g", Arguments: "{}"}},
		}},
		{Role: llms.ChatMessageTypeTool, Parts: []llms.ContentPart{
			llms.ToolCallResponse{ToolCallID: "a", Content: "ra"},
			llms.ToolCallResponse{ToolCallID: "b", Content: "rb"},
		}},
	}

	out := splitToolResultMessages(in)

	// system, human, AI (unchanged) + 2 split tool messages = 5.
	require.Len(t, out, 5)
	assert.Equal(t, llms.ChatMessageTypeSystem, out[0].Role)
	assert.Equal(t, llms.ChatMessageTypeHuman, out[1].Role)
	assert.Equal(t, llms.ChatMessageTypeAI, out[2].Role)
	assert.Len(t, out[2].Parts, 2, "AI tool-call message is not split")

	require.Equal(t, llms.ChatMessageTypeTool, out[3].Role)
	require.Len(t, out[3].Parts, 1)
	assert.Equal(t, "a", out[3].Parts[0].(llms.ToolCallResponse).ToolCallID)

	require.Equal(t, llms.ChatMessageTypeTool, out[4].Role)
	require.Len(t, out[4].Parts, 1)
	assert.Equal(t, "b", out[4].Parts[0].(llms.ToolCallResponse).ToolCallID)
}

func TestSplitToolResultMessages_SinglePartUntouched(t *testing.T) {
	in := []llms.MessageContent{
		{Role: llms.ChatMessageTypeTool, Parts: []llms.ContentPart{
			llms.ToolCallResponse{ToolCallID: "a", Content: "ra"},
		}},
	}
	out := splitToolResultMessages(in)
	require.Len(t, out, 1)
	assert.Len(t, out[0].Parts, 1)
}
