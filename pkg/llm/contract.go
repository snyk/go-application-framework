// Package llm supplies LLM provider adapters behind one vendor-agnostic
// Provider interface.
//
// All wire-level differences between vendors are pushed into langchaingo
// (github.com/tmc/langchaingo/llms) or a small in-package llms.Model where
// langchaingo falls short (Ollama tool-calling, Vertex Model Garden). Everything
// above the adapter speaks the Provider interface and the ChatRequest/
// ChatResponse types defined here, so callers stay vendor-neutral.
//
// Configuration (provider selection, API keys, base URLs) is read from a
// configuration.Configuration via NewFromConfig; see config.go for the keys and
// the env vars they map onto.
package llm

import "context"

//go:generate go tool github.com/golang/mock/mockgen -source=contract.go -destination ../mocks/llm.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/llm/

// Provider is the LLM-agnostic interface all provider adapters implement.
type Provider interface {
	// ChatCompletion sends a request and returns a response.
	ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error)

	// Name returns the provider identifier (e.g. "anthropic", "openai").
	Name() string
}

// ChatRequest is the provider-agnostic request type.
type ChatRequest struct {
	SystemPrompt string
	Model        string
	Messages     []Message
	Tools        []ToolDefinition
	MaxTokens    int
}

// ChatResponse is the provider-agnostic response type.
type ChatResponse struct {
	Content    string     // text response (if any)
	ToolCalls  []ToolCall // tool calls to execute
	StopReason StopReason
	Usage      TokenUsage
}

// ToolDefinition describes a tool available for the provider to call.
type ToolDefinition struct {
	Name        string
	Description string
	InputSchema []byte // JSON Schema
}
