package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tmc/langchaingo/llms"
)

// ollamaChatModel is a minimal llms.Model that talks to Ollama's /api/chat
// endpoint with tool-calling enabled. Exists because as of langchaingo v0.1.14
// the bundled llms/ollama provider neither forwards tool definitions nor
// extracts tool calls from the response. Ollama's HTTP API itself supports
// tools since 0.3.0 (July 2024) for compatible models (llama3.1, qwen2.5,
// etc.), so we just call it directly. Replace with langchaingo's provider
// once upstream gains tool support.
//
// Wire format reference: https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-chat-completion
type ollamaChatModel struct {
	model   string
	baseURL string
	http    *http.Client
}

// newOllamaChatModel builds the model. base is the shared HTTP transport
// (nil = http.DefaultTransport); a networking transport threads proxy/CA here.
func newOllamaChatModel(model, baseURL string, base http.RoundTripper) *ollamaChatModel {
	if base == nil {
		base = http.DefaultTransport
	}
	return &ollamaChatModel{
		model:   model,
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Transport: base},
	}
}

// --- /api/chat request types ---

type ollamaChatReq struct {
	Model    string        `json:"model"`
	Messages []ollamaMsg   `json:"messages"`
	Tools    []ollamaTool  `json:"tools,omitempty"`
	Stream   bool          `json:"stream"`
	Options  ollamaOptions `json:"options,omitempty"`
}

type ollamaOptions struct {
	NumPredict *int `json:"num_predict,omitempty"`
}

type ollamaMsg struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
}

type ollamaToolCall struct {
	Function ollamaToolFunc `json:"function"`
}

type ollamaToolFunc struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type ollamaTool struct {
	Type     string             `json:"type"`
	Function ollamaToolFuncDecl `json:"function"`
}

type ollamaToolFuncDecl struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

// --- /api/chat response types ---

type ollamaChatResp struct {
	Model           string    `json:"model"`
	Message         ollamaMsg `json:"message"`
	Done            bool      `json:"done"`
	DoneReason      string    `json:"done_reason"`
	PromptEvalCount int       `json:"prompt_eval_count"`
	EvalCount       int       `json:"eval_count"`
}

// GenerateContent runs one Ollama chat completion with optional tools.
func (m *ollamaChatModel) GenerateContent(ctx context.Context, messages []llms.MessageContent, options ...llms.CallOption) (*llms.ContentResponse, error) {
	co := &llms.CallOptions{}
	for _, opt := range options {
		opt(co)
	}

	reqBody := ollamaChatReq{
		Model:    m.modelFor(co),
		Messages: lcToOllamaMessages(messages),
		Tools:    lcToOllamaTools(co.Tools),
		Stream:   false,
	}
	if co.MaxTokens > 0 {
		n := co.MaxTokens
		reqBody.Options.NumPredict = &n
	}

	buf, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ollama: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+"/api/chat", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := m.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama: do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama: read response: %w", err)
	}
	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("ollama: http %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed ollamaChatResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("ollama: decode response: %w", err)
	}

	return ollamaToLCResponse(&parsed), nil
}

// Call satisfies the legacy llms.Model interface. We don't use it.
func (m *ollamaChatModel) Call(_ context.Context, _ string, _ ...llms.CallOption) (string, error) {
	return "", errors.New("ollamaChatModel.Call is not implemented; use GenerateContent")
}

// modelFor lets a per-call WithModel override the constructor default.
func (m *ollamaChatModel) modelFor(co *llms.CallOptions) string {
	if co.Model != "" {
		return co.Model
	}
	return m.model
}

// lcToOllamaMessages collapses langchaingo's MessageContent slice into the
// flat role/content/tool_calls list Ollama expects.
func lcToOllamaMessages(in []llms.MessageContent) []ollamaMsg {
	out := make([]ollamaMsg, 0, len(in))
	for _, mc := range in {
		role := ollamaRole(mc.Role)
		var text strings.Builder
		var toolCalls []ollamaToolCall
		for _, p := range mc.Parts {
			switch v := p.(type) {
			case llms.TextContent:
				text.WriteString(v.Text)
			case llms.ToolCall:
				if v.FunctionCall != nil {
					toolCalls = append(toolCalls, ollamaToolCall{
						Function: ollamaToolFunc{
							Name:      v.FunctionCall.Name,
							Arguments: json.RawMessage(v.FunctionCall.Arguments),
						},
					})
				}
			case llms.ToolCallResponse:
				// Ollama models a tool response as role="tool" + content.
				out = append(out, ollamaMsg{Role: "tool", Content: v.Content})
				continue
			}
		}
		// Skip the synthetic role swap when a Tool message already emitted
		// individual entries above and had no other parts.
		if role == "tool" && text.Len() == 0 && len(toolCalls) == 0 {
			continue
		}
		out = append(out, ollamaMsg{Role: role, Content: text.String(), ToolCalls: toolCalls})
	}
	return out
}

func ollamaRole(r llms.ChatMessageType) string {
	switch r {
	case llms.ChatMessageTypeSystem:
		return "system"
	case llms.ChatMessageTypeAI:
		return "assistant"
	case llms.ChatMessageTypeTool:
		return "tool"
	default:
		return "user"
	}
}

func lcToOllamaTools(tools []llms.Tool) []ollamaTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]ollamaTool, 0, len(tools))
	for _, t := range tools {
		if t.Function == nil {
			continue
		}
		out = append(out, ollamaTool{
			Type: "function",
			Function: ollamaToolFuncDecl{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			},
		})
	}
	return out
}

func ollamaToLCResponse(r *ollamaChatResp) *llms.ContentResponse {
	choice := &llms.ContentChoice{
		Content: r.Message.Content,
		GenerationInfo: map[string]any{
			"PromptTokens":     r.PromptEvalCount,
			"CompletionTokens": r.EvalCount,
		},
	}

	for _, tc := range r.Message.ToolCalls {
		// Ollama tool calls don't carry an ID; synthesize one so downstream
		// code that uses ToolCallID for the result roundtrip has something
		// stable per call.
		choice.ToolCalls = append(choice.ToolCalls, llms.ToolCall{
			ID:   ollamaSynthID(tc.Function.Name, len(choice.ToolCalls)),
			Type: "function",
			FunctionCall: &llms.FunctionCall{
				Name:      tc.Function.Name,
				Arguments: string(tc.Function.Arguments),
			},
		})
	}

	if len(choice.ToolCalls) > 0 {
		choice.StopReason = "tool_use"
	} else if r.DoneReason != "" {
		choice.StopReason = r.DoneReason
	}

	return &llms.ContentResponse{Choices: []*llms.ContentChoice{choice}}
}

func ollamaSynthID(name string, idx int) string {
	return fmt.Sprintf("ollama_%s_%d", name, idx)
}
