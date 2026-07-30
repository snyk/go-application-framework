package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/vertex"
	"github.com/tmc/langchaingo/llms"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/genai"
)

// anthropicPublisherPrefix is the full Model Garden path prefix for Anthropic
// models. We accept either a bare id (e.g. "claude-sonnet-4-6") or the full
// path; anthropicModelID normalizes to the bare id the anthropic-sdk-go wants
// (its vertex middleware re-appends publishers/anthropic/models/<id>).
const anthropicPublisherPrefix = "publishers/anthropic/models/"

// isAnthropicModel reports whether a Vertex model id is an Anthropic Claude
// model (rawPredict endpoint) rather than a Google Gemini model
// (generateContent). Routing is by name so the CLI can pass bare ids: every
// Anthropic model is "claude-*", and the full publisher path is also accepted.
func isAnthropicModel(model string) bool {
	return strings.HasPrefix(model, "claude") || strings.HasPrefix(model, "publishers/anthropic/")
}

// anthropicModelID returns the bare model id the anthropic-sdk-go expects,
// stripping the publishers/anthropic/models/ prefix if present. A bare id
// (with or without an "@version" suffix) is returned unchanged.
func anthropicModelID(model string) string {
	return strings.TrimPrefix(model, anthropicPublisherPrefix)
}

// vertexModel is a minimal llms.Model that talks to Vertex AI Model Garden via
// Google's official unified SDK (google.golang.org/genai) with the Vertex
// backend. It exists for the same reason as ollamaChatModel: langchaingo's
// bundled Vertex provider sits on the legacy cloud.google.com/go/vertexai
// client and lags on Model Garden partner models (Anthropic Claude on Vertex),
// so we drive genai directly while keeping the same llms.Model interface and
// reusing all of LangchainAdapter's mapping.
//
// Auth is Application Default Credentials (ADC). Project and location come from
// GOOGLE_CLOUD_PROJECT / GOOGLE_CLOUD_LOCATION (validated before we get here).
//
// Only the client matching the default model is created at construction time:
// a Gemini default builds the genai client; a Claude default builds the
// anthropic client. The two SDKs use incompatible credential types so each
// resolves ADC independently when needed.
type vertexModel struct {
	model  string            // default model id; per-call llms.WithModel overrides it
	client *genai.Client     // non-nil when default model is Gemini
	claude *anthropic.Client // non-nil when default model is Claude
}

// newVertexModel creates only the backend client that matches the default model.
// We use vertex.WithCredentials (rather than vertex.WithGoogleAuth, which panics
// on a missing credential) so a missing ADC returns a clean error.
//
// baseURL, when non-empty, overrides the default Vertex endpoint for both
// backends (a regional endpoint or a proxy).
//
// authToken, when non-empty, authenticates with that bearer token instead of
// Google ADC — for a gateway/proxy (e.g. an internal Vertex front-end) that
// expects "Authorization: Bearer <token>" rather than Google credentials.
// project and location are still used to build the request path. extra carries
// additional headers added to every request (gateway headers). base is the
// shared HTTP transport applied to the genai bearer path (nil = default); the
// ADC and Claude paths let their SDKs manage the transport for credential
// detection.
func newVertexModel(ctx context.Context, model, project, location, baseURL, authToken string, extra http.Header, base http.RoundTripper) (*vertexModel, error) {
	m := &vertexModel{model: model}

	if isAnthropicModel(model) {
		var opts []option.RequestOption
		if authToken != "" {
			// Gateway (bearer) auth. Reuse the SDK's own Vertex transform:
			// vertex.WithCredentials registers the middleware that rewrites
			// /v1/messages → the :rawPredict resource path and injects
			// anthropic_version. We just feed it a static bearer token (instead
			// of ADC). That middleware is prefix-blind (absolute path), so we
			// point the client at the gateway origin and re-add the path prefix
			// with vertexPathPrefixMiddleware, registered AFTER WithCredentials
			// so it runs after the SDK rewrite.
			creds := &google.Credentials{
				TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: authToken}),
			}
			opts = []option.RequestOption{vertex.WithCredentials(ctx, location, project, creds)}
			origin, prefix := splitGatewayBaseURL(baseURL)
			if origin != "" {
				opts = append(opts, option.WithBaseURL(origin))
			}
			if prefix != "" {
				opts = append(opts, option.WithMiddleware(vertexPathPrefixMiddleware(prefix)))
			}
		} else {
			creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
			if err != nil {
				return nil, fmt.Errorf("vertex: application default credentials: %w", err)
			}
			opts = []option.RequestOption{vertex.WithCredentials(ctx, location, project, creds)}
			if baseURL != "" {
				opts = append(opts, option.WithBaseURL(baseURL))
			}
		}
		for k, vs := range extra {
			for _, v := range vs {
				opts = append(opts, option.WithHeaderAdd(k, v))
			}
		}
		c := anthropic.NewClient(opts...)
		m.claude = &c
	} else {
		cfg := &genai.ClientConfig{
			Backend:  genai.BackendVertexAI,
			Project:  project,
			Location: location,
		}
		if baseURL != "" {
			cfg.HTTPOptions.BaseURL = baseURL
		}
		if len(extra) > 0 {
			// genai applies HTTPOptions.Headers to every request (api_client.go).
			cfg.HTTPOptions.Headers = extra
		}
		if authToken != "" {
			// Providing HTTPClient makes genai skip credential detection (see
			// client.go), so a bearer Authorization header supplies auth instead
			// of ADC. (Extra headers go through HTTPOptions.Headers above.) The
			// shared base transport (proxy/CA) sits under the header injection.
			cfg.HTTPClient = &http.Client{Transport: &headerTransport{
				base: base,
				add:  http.Header{"Authorization": {"Bearer " + authToken}},
			}}
		}
		client, err := genai.NewClient(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("vertex: create genai client: %w", err)
		}
		m.client = client
	}

	return m, nil
}

// splitGatewayBaseURL splits a gateway base URL into the scheme://host origin
// and the path prefix (e.g. "https://gw/vertex" → "https://gw", "/vertex").
// The SDK's Vertex middleware only fires on a bare "/v1/messages" path and
// rewrites to an absolute path, so we point the client at the origin (letting
// that middleware fire) and re-add the prefix afterward. Empty input → "", "".
func splitGatewayBaseURL(raw string) (origin, prefix string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, ""
	}
	origin = (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
	return origin, strings.TrimRight(u.Path, "/")
}

// vertexPathPrefixMiddleware re-adds a gateway path prefix that the SDK's
// (prefix-blind) Vertex middleware drops. Register it AFTER
// vertex.WithCredentials so it runs after the SDK rewrites /v1/messages → the
// :rawPredict path, prepending the prefix to the final resource path.
func vertexPathPrefixMiddleware(prefix string) option.Middleware {
	return func(r *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		r.URL.Path = path.Join(prefix, r.URL.Path)
		return next(r)
	}
}

// GenerateContent runs one Vertex chat round-trip with optional tools, routing
// to the Gemini (genai) or Claude (anthropic-sdk-go) client based on the model.
func (m *vertexModel) GenerateContent(ctx context.Context, messages []llms.MessageContent, options ...llms.CallOption) (*llms.ContentResponse, error) {
	co := &llms.CallOptions{}
	for _, opt := range options {
		opt(co)
	}

	model := m.modelFor(co)
	if isAnthropicModel(model) {
		return m.generateClaude(ctx, model, messages, co)
	}
	return m.generateGemini(ctx, model, messages, co)
}

// generateGemini runs one genai :generateContent call for a Gemini model.
func (m *vertexModel) generateGemini(ctx context.Context, model string, messages []llms.MessageContent, co *llms.CallOptions) (*llms.ContentResponse, error) {
	if m.client == nil {
		return nil, fmt.Errorf("vertex: genai client not initialised (provider was configured for a Claude model)")
	}
	contents, systemInstruction := lcToGenaiContents(messages)

	config := &genai.GenerateContentConfig{}
	if systemInstruction != nil {
		config.SystemInstruction = systemInstruction
	}
	if co.MaxTokens > 0 {
		config.MaxOutputTokens = int32(co.MaxTokens)
	}
	if tools := lcToGenaiTools(co.Tools); tools != nil {
		config.Tools = tools
	}

	resp, err := m.client.Models.GenerateContent(ctx, model, contents, config)
	if err != nil {
		return nil, fmt.Errorf("vertex: generate content: %w", err)
	}

	return genaiToLCResponse(resp), nil
}

// anthropicDefaultMaxTokens is used when the caller does not set MaxTokens.
// The Anthropic Messages API requires max_tokens (genai does not).
const anthropicDefaultMaxTokens = 4096

// generateClaude runs one anthropic-sdk-go Messages call (Vertex :rawPredict)
// for a Claude model, mapping to/from langchaingo's wire types.
func (m *vertexModel) generateClaude(ctx context.Context, model string, messages []llms.MessageContent, co *llms.CallOptions) (*llms.ContentResponse, error) {
	if m.claude == nil {
		return nil, fmt.Errorf("vertex: anthropic client not initialised (provider was configured for a Gemini model)")
	}
	msgs, system := lcToAnthropicMessages(messages)

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(anthropicModelID(model)),
		Messages:  msgs,
		MaxTokens: anthropicDefaultMaxTokens,
	}
	if len(system) > 0 {
		params.System = system
	}
	if co.MaxTokens > 0 {
		params.MaxTokens = int64(co.MaxTokens)
	}
	if tools := lcToAnthropicTools(co.Tools); len(tools) > 0 {
		params.Tools = tools
	}

	msg, err := m.claude.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("vertex: anthropic generate: %w", err)
	}

	return anthropicToLCResponse(msg), nil
}

// Call satisfies the legacy llms.Model interface. We don't use it.
func (m *vertexModel) Call(_ context.Context, _ string, _ ...llms.CallOption) (string, error) {
	return "", errors.New("vertexModel.Call is not implemented; use GenerateContent")
}

// modelFor lets a per-call WithModel override the constructor default.
func (m *vertexModel) modelFor(co *llms.CallOptions) string {
	if co.Model != "" {
		return co.Model
	}
	return m.model
}

// lcToGenaiContents converts langchaingo's MessageContent slice into genai's
// []*Content plus an optional system instruction. Gemini accepts only "user"
// and "model" roles, so the system prompt is returned separately (it becomes
// GenerateContentConfig.SystemInstruction) and tool results are sent as "user"
// content carrying FunctionResponse parts.
//
// Gemini's FunctionResponse requires the function name, but langchaingo's
// ToolCallResponse carries only the tool-call ID. We recover the name by
// recording each assistant FunctionCall's ID→name as we walk the slice;
// messages are in order, so an assistant call is always seen before its result.
func lcToGenaiContents(in []llms.MessageContent) (contents []*genai.Content, systemInstruction *genai.Content) {
	idToName := map[string]string{}
	var systemText string

	for _, mc := range in {
		switch mc.Role {
		case llms.ChatMessageTypeSystem:
			for _, p := range mc.Parts {
				if t, ok := p.(llms.TextContent); ok {
					systemText += t.Text
				}
			}

		case llms.ChatMessageTypeAI:
			parts := make([]*genai.Part, 0, len(mc.Parts))
			for _, p := range mc.Parts {
				switch v := p.(type) {
				case llms.TextContent:
					if v.Text != "" {
						parts = append(parts, &genai.Part{Text: v.Text})
					}
				case llms.ToolCall:
					if v.FunctionCall == nil {
						continue
					}
					idToName[v.ID] = v.FunctionCall.Name
					parts = append(parts, &genai.Part{FunctionCall: &genai.FunctionCall{
						ID:   v.ID,
						Name: v.FunctionCall.Name,
						Args: argsToMap(v.FunctionCall.Arguments),
					}})
				}
			}
			if len(parts) > 0 {
				contents = append(contents, &genai.Content{Role: genai.RoleModel, Parts: parts})
			}

		case llms.ChatMessageTypeTool:
			parts := make([]*genai.Part, 0, len(mc.Parts))
			for _, p := range mc.Parts {
				if tr, ok := p.(llms.ToolCallResponse); ok {
					parts = append(parts, &genai.Part{FunctionResponse: &genai.FunctionResponse{
						ID:       tr.ToolCallID,
						Name:     idToName[tr.ToolCallID],
						Response: map[string]any{"output": tr.Content},
					}})
				}
			}
			if len(parts) > 0 {
				contents = append(contents, &genai.Content{Role: genai.RoleUser, Parts: parts})
			}

		default: // Human and anything else → user text.
			parts := make([]*genai.Part, 0, len(mc.Parts))
			for _, p := range mc.Parts {
				if t, ok := p.(llms.TextContent); ok {
					parts = append(parts, &genai.Part{Text: t.Text})
				}
			}
			if len(parts) > 0 {
				contents = append(contents, &genai.Content{Role: genai.RoleUser, Parts: parts})
			}
		}
	}

	if systemText != "" {
		systemInstruction = &genai.Content{Parts: []*genai.Part{{Text: systemText}}}
	}
	return contents, systemInstruction
}

// argsToMap parses a tool-call's JSON argument string into the map[string]any
// genai expects. An empty or invalid string yields nil (no arguments).
func argsToMap(arguments string) map[string]any {
	if arguments == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(arguments), &m); err != nil {
		return nil
	}
	return m
}

// lcToGenaiTools converts langchaingo tool definitions into a single genai.Tool
// holding one FunctionDeclaration each. We pass the JSON Schema straight through
// via ParametersJsonSchema (the same raw-schema pass-through the Ollama adapter
// uses) rather than rebuilding it as a genai.Schema tree.
func lcToGenaiTools(tools []llms.Tool) []*genai.Tool {
	if len(tools) == 0 {
		return nil
	}
	decls := make([]*genai.FunctionDeclaration, 0, len(tools))
	for _, t := range tools {
		if t.Function == nil {
			continue
		}
		decls = append(decls, &genai.FunctionDeclaration{
			Name:                 t.Function.Name,
			Description:          t.Function.Description,
			ParametersJsonSchema: t.Function.Parameters,
		})
	}
	if len(decls) == 0 {
		return nil
	}
	return []*genai.Tool{{FunctionDeclarations: decls}}
}

// genaiToLCResponse folds a genai response into the single-choice
// llms.ContentResponse that fromLCResponse expects. Stop reasons are emitted as
// strings normalizeStopReason already understands ("tool_use", "max_tokens",
// "stop").
func genaiToLCResponse(resp *genai.GenerateContentResponse) *llms.ContentResponse {
	choice := &llms.ContentChoice{}
	if resp == nil || len(resp.Candidates) == 0 {
		return &llms.ContentResponse{Choices: []*llms.ContentChoice{choice}}
	}

	choice.Content = resp.Text()

	for i, fc := range resp.FunctionCalls() {
		if fc == nil {
			continue
		}
		args, err := json.Marshal(fc.Args)
		if err != nil {
			args = []byte("{}")
		}
		id := fc.ID
		if id == "" {
			// Gemini function calls don't always carry an ID; synthesize a
			// stable one so the tool-result roundtrip has something to match on.
			id = vertexSynthID(fc.Name, i)
		}
		choice.ToolCalls = append(choice.ToolCalls, llms.ToolCall{
			ID:   id,
			Type: "function",
			FunctionCall: &llms.FunctionCall{
				Name:      fc.Name,
				Arguments: string(args),
			},
		})
	}

	if len(choice.ToolCalls) > 0 {
		choice.StopReason = "tool_use"
	} else if resp.Candidates[0].FinishReason == genai.FinishReasonMaxTokens {
		choice.StopReason = "max_tokens"
	} else {
		choice.StopReason = "stop"
	}

	if u := resp.UsageMetadata; u != nil {
		choice.GenerationInfo = map[string]any{
			"InputTokens":  int(u.PromptTokenCount),
			"OutputTokens": int(u.CandidatesTokenCount),
		}
	}

	return &llms.ContentResponse{Choices: []*llms.ContentChoice{choice}}
}

func vertexSynthID(name string, idx int) string {
	return fmt.Sprintf("vertex_%s_%d", name, idx)
}

// --- Claude (anthropic-sdk-go) mapping ---------------------------------------
//
// These mirror the genai helpers above but target Anthropic's Messages API.
// langchaingo message roles map onto Anthropic as: system → a separate System
// block list (Anthropic has no system role), human/tool-result → user turns,
// assistant (text + tool_use) → assistant turns. Tool results carry their
// tool-call ID directly, so unlike the genai path we don't need to recover
// names from an id→name map.

// lcToAnthropicMessages converts langchaingo's MessageContent slice into
// Anthropic message params plus the system prompt (returned separately because
// Anthropic takes it as a top-level field, not a message role).
func lcToAnthropicMessages(in []llms.MessageContent) (msgs []anthropic.MessageParam, system []anthropic.TextBlockParam) {
	for _, mc := range in {
		switch mc.Role {
		case llms.ChatMessageTypeSystem:
			for _, p := range mc.Parts {
				if t, ok := p.(llms.TextContent); ok && t.Text != "" {
					system = append(system, anthropic.TextBlockParam{Text: t.Text})
				}
			}

		case llms.ChatMessageTypeAI:
			blocks := make([]anthropic.ContentBlockParamUnion, 0, len(mc.Parts))
			for _, p := range mc.Parts {
				switch v := p.(type) {
				case llms.TextContent:
					if v.Text != "" {
						blocks = append(blocks, anthropic.NewTextBlock(v.Text))
					}
				case llms.ToolCall:
					if v.FunctionCall == nil {
						continue
					}
					var input any = json.RawMessage("{}")
					if v.FunctionCall.Arguments != "" {
						input = json.RawMessage(v.FunctionCall.Arguments)
					}
					blocks = append(blocks, anthropic.NewToolUseBlock(v.ID, input, v.FunctionCall.Name))
				}
			}
			if len(blocks) > 0 {
				msgs = append(msgs, anthropic.NewAssistantMessage(blocks...))
			}

		case llms.ChatMessageTypeTool:
			blocks := make([]anthropic.ContentBlockParamUnion, 0, len(mc.Parts))
			for _, p := range mc.Parts {
				if tr, ok := p.(llms.ToolCallResponse); ok {
					blocks = append(blocks, anthropic.NewToolResultBlock(tr.ToolCallID, tr.Content, false))
				}
			}
			if len(blocks) > 0 {
				msgs = append(msgs, anthropic.NewUserMessage(blocks...))
			}

		default: // Human and anything else → user text.
			blocks := make([]anthropic.ContentBlockParamUnion, 0, len(mc.Parts))
			for _, p := range mc.Parts {
				if t, ok := p.(llms.TextContent); ok && t.Text != "" {
					blocks = append(blocks, anthropic.NewTextBlock(t.Text))
				}
			}
			if len(blocks) > 0 {
				msgs = append(msgs, anthropic.NewUserMessage(blocks...))
			}
		}
	}
	return msgs, system
}

// lcToAnthropicTools converts langchaingo tool definitions into Anthropic tool
// params. The langchaingo Parameters field holds the parsed JSON Schema
// (map[string]any); we pass its "properties" and "required" straight through
// to ToolInputSchemaParam rather than rebuilding the schema.
func lcToAnthropicTools(tools []llms.Tool) []anthropic.ToolUnionParam {
	if len(tools) == 0 {
		return nil
	}
	out := make([]anthropic.ToolUnionParam, 0, len(tools))
	for _, t := range tools {
		if t.Function == nil {
			continue
		}
		var in anthropic.ToolInputSchemaParam
		if params, ok := t.Function.Parameters.(map[string]any); ok {
			in.Properties = params["properties"]
			if req, ok := params["required"].([]any); ok {
				for _, r := range req {
					if s, ok := r.(string); ok {
						in.Required = append(in.Required, s)
					}
				}
			}
		}
		tp := anthropic.ToolParam{
			Name:        t.Function.Name,
			Description: anthropic.String(t.Function.Description),
			InputSchema: in,
		}
		out = append(out, anthropic.ToolUnionParam{OfTool: &tp})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// anthropicToLCResponse folds an Anthropic Message into the single-choice
// llms.ContentResponse LangchainAdapter expects. StopReason values
// ("tool_use"/"max_tokens"/"end_turn") are passed through as strings that
// normalizeStopReason already understands; token counts use Anthropic's
// InputTokens/OutputTokens keys that readTokenUsage reads.
func anthropicToLCResponse(msg *anthropic.Message) *llms.ContentResponse {
	choice := &llms.ContentChoice{}
	if msg == nil {
		return &llms.ContentResponse{Choices: []*llms.ContentChoice{choice}}
	}

	for _, block := range msg.Content {
		switch b := block.AsAny().(type) {
		case anthropic.TextBlock:
			choice.Content += b.Text
		case anthropic.ToolUseBlock:
			choice.ToolCalls = append(choice.ToolCalls, llms.ToolCall{
				ID:   b.ID,
				Type: "function",
				FunctionCall: &llms.FunctionCall{
					Name:      b.Name,
					Arguments: string(b.Input),
				},
			})
		}
	}

	choice.StopReason = string(msg.StopReason)
	choice.GenerationInfo = map[string]any{
		"InputTokens":  int(msg.Usage.InputTokens),
		"OutputTokens": int(msg.Usage.OutputTokens),
	}

	return &llms.ContentResponse{Choices: []*llms.ContentChoice{choice}}
}
