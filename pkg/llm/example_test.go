package llm_test

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/llm"
)

// The simplest path: resolve the provider from configuration (env vars, config
// keys, or values Set by the caller) and build it in one step, then run a chat
// completion. With no provider explicitly configured, Resolve auto-detects from
// an Anthropic key (or base URL), then an OpenAI key.
func ExampleNewFromConfig() {
	config := configuration.New() // inside a workflow: ictx.GetConfiguration()

	provider, err := llm.NewFromConfig(config)
	if err != nil {
		return // no provider configured (set ANTHROPIC_API_KEY / OPENAI_API_KEY, or CONFIG_PROVIDER)
	}

	resp, err := provider.ChatCompletion(context.Background(), &llm.ChatRequest{
		SystemPrompt: "You are a helpful assistant.",
		MaxTokens:    1024,
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: "Say hello."},
		},
	})
	if err != nil {
		return
	}
	fmt.Println(resp.Content)
}

// Inside a GAF workflow, wire the shared network transport (proxy/CA/FIPS, no
// Snyk auth headers) and — for Bedrock — an AWS User-Agent app id. WithLogger
// accepts the invocation's *zerolog.Logger.
func ExampleNewFromConfig_withOptions() {
	config := configuration.New()
	config.Set(llm.CONFIG_PROVIDER, "bedrock")

	provider, err := llm.NewFromConfig(config,
		// llm.WithNetworkAccess(ictx.GetNetworkAccess()),
		// llm.WithLogger(ictx.GetEnhancedLogger()),
		llm.WithBedrockAppID("MY_APP"),
	)
	if err != nil {
		return
	}
	_ = provider
}

// When you need the resolved provider name and model separately (e.g. for
// telemetry) before building, resolve and build in two steps.
func ExampleResolve() {
	config := configuration.New()

	res, err := llm.Resolve(config)
	if err != nil {
		return
	}
	fmt.Printf("using provider %q model %q\n", res.Provider, res.Model)

	provider, err := llm.New(config, res)
	if err != nil {
		return
	}
	_ = provider
}

// Tool calling: pass tool definitions and, when the model requests a call, echo
// the result back as a ToolResult on the next turn.
func ExampleProvider_toolCalling() {
	config := configuration.New()
	provider, err := llm.NewFromConfig(config)
	if err != nil {
		return
	}

	resp, err := provider.ChatCompletion(context.Background(), &llm.ChatRequest{
		Model:     "gpt-4o",
		MaxTokens: 1024,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "Scan the repo at ./api."}},
		Tools: []llm.ToolDefinition{{
			Name:        "scan",
			Description: "Run a Snyk scan on a path.",
			InputSchema: []byte(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`),
		}},
	})
	if err != nil {
		return
	}

	if resp.StopReason == llm.StopToolUse {
		for _, call := range resp.ToolCalls {
			// Execute the tool with call.Input (JSON), then feed the output back:
			_ = llm.Message{
				Role: llm.RoleUser,
				ToolResults: []llm.ToolResult{
					{ToolCallID: call.ID, Content: "no issues found"},
				},
			}
		}
	}
}
