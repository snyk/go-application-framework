package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tmc/langchaingo/llms"
)

// defaultChatTimeout bounds a single provider round-trip. It is generous enough
// for a large completion but turns an unresponsive endpoint (e.g. a stalled
// proxy) into a clear error instead of an indefinite hang. A shorter deadline
// already on the caller's context still wins (context.WithTimeout takes the
// earlier of the two). The timeout applies per attempt, so each retry gets a
// fresh deadline.
const defaultChatTimeout = 120 * time.Second

// Retry defaults. A 429 (rate limit) or 529 (overloaded) from the vendor is
// transient — Anthropic's input-tokens-per-minute limit frees up as the
// rolling window advances — so we back off and retry rather than aborting the
// whole run. The delay schedule (2s, 4s, 8s, 16s, capped at 30s) spans roughly
// a minute over maxRetries attempts, enough for an ITPM window to reset.
const (
	defaultMaxRetries = 5
	retryBaseDelay    = 2 * time.Second
	retryMaxDelay     = 30 * time.Second
)

// LangchainAdapter implements Provider over any langchaingo llms.Model. Each
// vendor-specific factory in factories.go builds the matching llms.Model and
// wraps it here, so this struct holds all the cross-provider mapping logic in
// one place.
type LangchainAdapter struct {
	name  string
	model llms.Model

	// splitToolResults makes ChatCompletion emit one ChatMessageTypeTool
	// message per tool result (one part each) instead of batching a turn's
	// results into a single multi-part message. langchaingo's OpenAI provider
	// requires exactly one part per tool message (openaillm.go) — OpenAI's wire
	// format is one `tool` message per tool_call_id — so this must be set for
	// OpenAI-family backends (openai, litellm proxy). Anthropic/Gemini/
	// Ollama consume the batched shape and leave it off.
	splitToolResults bool

	// maxRetries bounds the number of retry attempts after a transient
	// (429/529) provider error. sleep is the cancellable delay used between
	// attempts; it is a field so tests can inject a no-op and assert the
	// backoff schedule without real waits.
	maxRetries int
	sleep      func(context.Context, time.Duration) error
}

var _ Provider = (*LangchainAdapter)(nil)

// NewLangchainAdapter wraps the given llms.Model. The name is what
// Provider.Name() returns; pick the vendor identifier (e.g. "anthropic",
// "openai", "ollama").
func NewLangchainAdapter(name string, model llms.Model) *LangchainAdapter {
	return &LangchainAdapter{
		name:       name,
		model:      model,
		maxRetries: defaultMaxRetries,
		sleep:      ctxSleep,
	}
}

// ctxSleep waits for d or until ctx is cancelled, whichever comes first.
func ctxSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// retryDelay returns the backoff for a zero-based attempt index: an
// exponential schedule (base, 2×base, 4×base, …) capped at retryMaxDelay.
func retryDelay(attempt int) time.Duration {
	d := retryBaseDelay << attempt
	if d > retryMaxDelay || d <= 0 { // <=0 guards against shift overflow
		return retryMaxDelay
	}
	return d
}

// isRetryableError reports whether err is a transient provider error worth
// retrying — vendor rate limits (HTTP 429) and overloaded responses (HTTP
// 529). Matching is on the error text because langchaingo (and the Vertex
// genai SDK) surface the status inside the message rather than as a typed
// error. resource_exhausted is the gRPC/Vertex spelling of a 429, so the new
// Vertex backend's rate limits are retried like everyone else's.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "status code: 429"),
		strings.Contains(msg, "status code: 529"),
		strings.Contains(msg, "too many requests"),
		strings.Contains(msg, "rate limit"),
		strings.Contains(msg, "rate_limit"),
		strings.Contains(msg, "resource_exhausted"), // Vertex/Gemini REST (APIError)
		strings.Contains(msg, "resourceexhausted"),  // Vertex/Gemini gRPC status
		strings.Contains(msg, "overloaded"):
		return true
	}
	return false
}

// Name returns the provider identifier supplied at construction.
func (a *LangchainAdapter) Name() string { return a.name }

// ChatCompletion runs one round-trip through the underlying llms.Model.
func (a *LangchainAdapter) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	messages, err := toLCMessages(req.SystemPrompt, req.Messages)
	if err != nil {
		return nil, err
	}
	if a.splitToolResults {
		messages = splitToolResultMessages(messages)
	}

	opts := []llms.CallOption{}
	if req.Model != "" {
		opts = append(opts, llms.WithModel(req.Model))
	}
	if req.MaxTokens > 0 {
		opts = append(opts, llms.WithMaxTokens(req.MaxTokens))
	}
	// temperature is intentionally never set — current provider models deprecate
	// the parameter. langchaingo still hardcodes temperature:0 into the anthropic
	// and openai request bodies (no omitempty), so it is stripped on the wire by
	// the adapter's HTTP transport (see strippedBodyFields); models use their own
	// default.
	if tools, terr := toLCTools(req.Tools); terr != nil {
		return nil, terr
	} else if len(tools) > 0 {
		opts = append(opts, llms.WithTools(tools))
	}

	resp, err := a.generateWithRetry(ctx, messages, opts)
	if err != nil {
		// Distinguish our own deadline from a caller cancellation: only the
		// former should surface as a timeout message.
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, fmt.Errorf("provider %q: chat completion timed out after %s", a.name, defaultChatTimeout)
		}
		return nil, err
	}
	return fromLCResponse(resp), nil
}

// generateWithRetry calls the underlying model, retrying transient
// (rate-limit/overloaded) failures with exponential backoff. Non-retryable
// errors and a cancelled context return immediately; the last error is
// returned once retries are exhausted.
func (a *LangchainAdapter) generateWithRetry(ctx context.Context, messages []llms.MessageContent, opts []llms.CallOption) (*llms.ContentResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= a.maxRetries; attempt++ {
		resp, err := a.generateOnce(ctx, messages, opts)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !a.retryable(ctx, err) || attempt == a.maxRetries {
			return nil, err
		}
		if serr := a.sleep(ctx, retryDelay(attempt)); serr != nil {
			return nil, serr
		}
	}
	return nil, lastErr
}

// retryable reports whether err from a single attempt is worth retrying. A
// transient vendor error (rate limit / overloaded) qualifies, and so does our
// own per-call deadline (generateOnce's timeout) when the caller's context is
// still live — a stalled endpoint is as transient as a 429. A deadline that
// stems from the caller cancelling ctx is not retried.
func (a *LangchainAdapter) retryable(ctx context.Context, err error) bool {
	if isRetryableError(err) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil
}

// generateOnce performs a single provider round-trip bounded by
// defaultChatTimeout. A shorter deadline already on ctx still wins. Each
// retry attempt gets its own fresh deadline.
func (a *LangchainAdapter) generateOnce(ctx context.Context, messages []llms.MessageContent, opts []llms.CallOption) (*llms.ContentResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, defaultChatTimeout)
	defer cancel()
	return a.model.GenerateContent(callCtx, messages, opts...)
}

// toLCMessages converts a system prompt + Message slice into langchaingo's
// MessageContent representation.
func toLCMessages(systemPrompt string, msgs []Message) ([]llms.MessageContent, error) {
	result := make([]llms.MessageContent, 0, len(msgs)+1)
	if systemPrompt != "" {
		result = append(result, llms.MessageContent{
			Role:  llms.ChatMessageTypeSystem,
			Parts: []llms.ContentPart{llms.TextContent{Text: systemPrompt}},
		})
	}
	for _, m := range msgs {
		mc, err := toLCMessage(m)
		if err != nil {
			return nil, err
		}
		result = append(result, mc)
	}
	return result, nil
}

func toLCMessage(m Message) (llms.MessageContent, error) {
	switch m.Role {
	case RoleUser:
		// A user message either carries plain text or one-or-more tool
		// results. Tool results are sent as a separate MessageContent with
		// Role=Tool so each ToolCallResponse carries its own ToolCallID.
		if len(m.ToolResults) > 0 {
			parts := make([]llms.ContentPart, 0, len(m.ToolResults))
			for _, tr := range m.ToolResults {
				parts = append(parts, llms.ToolCallResponse{
					ToolCallID: tr.ToolCallID,
					Content:    tr.Content,
				})
			}
			return llms.MessageContent{Role: llms.ChatMessageTypeTool, Parts: parts}, nil
		}
		return llms.MessageContent{
			Role:  llms.ChatMessageTypeHuman,
			Parts: []llms.ContentPart{llms.TextContent{Text: m.Content}},
		}, nil

	case RoleAssistant:
		parts := make([]llms.ContentPart, 0, 1+len(m.ToolCalls))
		if m.Content != "" {
			parts = append(parts, llms.TextContent{Text: m.Content})
		}
		for _, tc := range m.ToolCalls {
			parts = append(parts, llms.ToolCall{
				ID:   tc.ID,
				Type: "function",
				FunctionCall: &llms.FunctionCall{
					Name:      tc.Name,
					Arguments: string(tc.Input),
				},
			})
		}
		if len(parts) == 0 {
			parts = append(parts, llms.TextContent{Text: ""})
		}
		return llms.MessageContent{Role: llms.ChatMessageTypeAI, Parts: parts}, nil

	default:
		return llms.MessageContent{}, fmt.Errorf("unknown message role: %q", m.Role)
	}
}

// splitToolResultMessages expands every ChatMessageTypeTool message that
// carries more than one part into several single-part tool messages. The
// caller batches all of one turn's tool results into a single tool message (the
// shape Anthropic/Gemini want), but langchaingo's OpenAI provider requires
// exactly one part per tool message (one `tool` message per tool_call_id). This
// runs only for OpenAI-family adapters (see splitToolResults). Order is
// preserved; non-tool and already-single-part messages pass through untouched.
func splitToolResultMessages(in []llms.MessageContent) []llms.MessageContent {
	out := make([]llms.MessageContent, 0, len(in))
	for _, mc := range in {
		if mc.Role == llms.ChatMessageTypeTool && len(mc.Parts) > 1 {
			for _, p := range mc.Parts {
				out = append(out, llms.MessageContent{
					Role:  llms.ChatMessageTypeTool,
					Parts: []llms.ContentPart{p},
				})
			}
			continue
		}
		out = append(out, mc)
	}
	return out
}

// toLCTools converts ToolDefinition slices into langchaingo's tool
// representation, parsing each InputSchema into a generic any so providers can
// re-serialize it in their own wire format.
func toLCTools(tools []ToolDefinition) ([]llms.Tool, error) {
	if len(tools) == 0 {
		return nil, nil
	}
	out := make([]llms.Tool, 0, len(tools))
	for _, t := range tools {
		var params any
		if len(t.InputSchema) > 0 {
			if err := json.Unmarshal(t.InputSchema, &params); err != nil {
				return nil, fmt.Errorf("tool %q: parse input schema: %w", t.Name, err)
			}
		}
		out = append(out, llms.Tool{
			Type: "function",
			Function: &llms.FunctionDefinition{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  params,
			},
		})
	}
	return out, nil
}

// fromLCResponse aggregates langchaingo's multi-choice response into a single
// ChatResponse. Anthropic returns one ContentChoice per content block (text +
// tool_use); OpenAI/Ollama return a single choice. Concatenating text content
// and collecting tool calls handles both.
func fromLCResponse(resp *llms.ContentResponse) *ChatResponse {
	out := &ChatResponse{StopReason: StopEndTurn}
	if resp == nil || len(resp.Choices) == 0 {
		return out
	}

	var stopRaw string
	for _, c := range resp.Choices {
		if c == nil {
			continue
		}
		out.Content += c.Content
		for _, tc := range c.ToolCalls {
			args := ""
			if tc.FunctionCall != nil {
				args = tc.FunctionCall.Arguments
			}
			name := ""
			if tc.FunctionCall != nil {
				name = tc.FunctionCall.Name
			}
			out.ToolCalls = append(out.ToolCalls, ToolCall{
				ID:    tc.ID,
				Name:  name,
				Input: json.RawMessage(args),
			})
		}
		if stopRaw == "" && c.StopReason != "" {
			stopRaw = c.StopReason
		}
	}
	out.StopReason = normalizeStopReason(stopRaw)
	out.Usage = readTokenUsage(resp.Choices[0].GenerationInfo)
	return out
}

// normalizeStopReason maps both Anthropic ("tool_use"/"max_tokens"/"end_turn")
// and OpenAI ("tool_calls"/"length"/"stop") literals onto the StopReason enum.
// Unknown / empty values fall back to StopEndTurn so the agent loop terminates
// rather than infinite-looping.
func normalizeStopReason(raw string) StopReason {
	switch raw {
	case "tool_calls", "tool_use":
		return StopToolUse
	case "length", "max_tokens":
		return StopMaxTokens
	default:
		return StopEndTurn
	}
}

// readTokenUsage pulls input/output token counts out of GenerationInfo,
// supporting both naming conventions: Anthropic uses InputTokens/OutputTokens,
// OpenAI and Ollama use PromptTokens/CompletionTokens.
func readTokenUsage(info map[string]any) TokenUsage {
	if info == nil {
		return TokenUsage{}
	}
	input := intFromAny(info["InputTokens"])
	if input == 0 {
		input = intFromAny(info["PromptTokens"])
	}
	output := intFromAny(info["OutputTokens"])
	if output == 0 {
		output = intFromAny(info["CompletionTokens"])
	}
	return TokenUsage{Input: input, Output: output}
}

// intFromAny tolerates the int/int64/float64 spread that JSON-unmarshaled
// numeric values can land as in a map[string]any.
func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
