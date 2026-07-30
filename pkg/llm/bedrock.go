package llm

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/tmc/langchaingo/llms/bedrock"
)

// bedrockConfigOptions builds the AWS config load options for the Bedrock
// client: an app id (rendered as an "app/<id>" token in the User-Agent, so
// traffic can be attributed/authorized downstream — a gateway, CloudTrail,
// usage metrics) when one is provided, and an explicit region when one is
// provided (otherwise the SDK resolves it from env/profile). appID is empty by
// default so this package ships vendor-neutral; a caller sets it via
// WithBedrockAppID.
func bedrockConfigOptions(region, appID string) []func(*config.LoadOptions) error {
	var opts []func(*config.LoadOptions) error
	if appID != "" {
		opts = append(opts, config.WithAppID(appID))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	return opts
}

// NewBedrockAdapter builds a LangchainAdapter backed by
// github.com/tmc/langchaingo/llms/bedrock, targeting Amazon Bedrock.
//
// Authentication is handled by the AWS SDK. Two paths are supported with no
// code difference here:
//   - a Bedrock API key (bearer token) via AWS_BEARER_TOKEN_BEDROCK — the
//     bedrockruntime client auto-detects that env var and switches to
//     httpBearerAuth; or
//   - the standard AWS credential chain (env keys, shared config/credentials,
//     SSO, EC2/ECS/EKS roles), SigV4-signed — the same way the vertex provider
//     relies on Google ADC.
//
// region is optional: when empty the AWS SDK resolves it from the
// environment/profile (AWS_REGION / AWS_DEFAULT_REGION or the active profile);
// pass it to pin an explicit region.
//
// appID, when non-empty, is added to the AWS User-Agent as an "app/<id>" token;
// empty leaves the User-Agent unbranded.
//
// model is the Bedrock model id, supplied per request via llms.WithModel. It may
// be a bare model id (e.g. anthropic.claude-3-5-sonnet-20241022-v2:0) or a
// cross-region inference profile id (e.g.
// us.anthropic.claude-3-5-sonnet-20241022-v2:0). langchaingo infers the model
// provider (anthropic, amazon, meta, …) from the id prefix, so tool-calling
// Claude models work out of the box.
func NewBedrockAdapter(model, region, appID string) (*LangchainAdapter, error) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, bedrockConfigOptions(region, appID)...)
	if err != nil {
		return nil, fmt.Errorf("bedrock: load AWS config: %w", err)
	}

	client := bedrockruntime.NewFromConfig(cfg)
	opts := []bedrock.Option{bedrock.WithClient(client)}
	if model != "" {
		opts = append(opts, bedrock.WithModel(model))
	}

	llm, err := bedrock.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("bedrock: %w", err)
	}
	// Bedrock's Anthropic provider uses Anthropic's content-block format
	// (tool_result blocks in a single user message), like the native anthropic
	// adapter — so we do NOT split tool results the way the OpenAI-family
	// adapters require.
	return NewLangchainAdapter("bedrock", llm), nil
}
