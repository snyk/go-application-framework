package llm

import "encoding/json"

// Message is a single turn in the conversation between the caller and a provider.
type Message struct {
	Role    Role
	Content string

	// ToolCalls is set when the provider requests one or more tool executions.
	ToolCalls []ToolCall

	// ToolResults is set when the message carries tool execution results back to the provider.
	ToolResults []ToolResult
}

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// ToolCall is a request from the provider to execute a named tool.
type ToolCall struct {
	ID    string          // opaque ID; must be echoed in the corresponding ToolResult
	Name  string          // tool name
	Input json.RawMessage // JSON-encoded tool input
}

// ToolResult carries the outcome of a tool execution back to the provider.
type ToolResult struct {
	ToolCallID string // must match the ToolCall.ID this result corresponds to
	Content    string // text returned to the LLM
	IsError    bool   // if true, Content describes the error
}

// StopReason is a normalized stop reason across all providers.
type StopReason string

const (
	StopEndTurn   StopReason = "end_turn"
	StopToolUse   StopReason = "tool_use"
	StopMaxTokens StopReason = "max_tokens"
	StopError     StopReason = "error"
)

// TokenUsage tracks input and output token counts for a single LLM call.
type TokenUsage struct {
	Input  int
	Output int
}
