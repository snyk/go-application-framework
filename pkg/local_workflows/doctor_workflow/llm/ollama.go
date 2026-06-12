package llm

import (
	"context"
	"fmt"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
)

type ollamaProvider struct {
	client *ollama.LLM
	model  string
}

func newOllamaProvider(opts Options) (*ollamaProvider, error) {
	client, err := ollama.New(
		ollama.WithServerURL(opts.BaseURL),
		ollama.WithModel(opts.Model),
		ollama.WithFormat("json"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ollama client for %s: %w", opts.BaseURL, err)
	}
	return &ollamaProvider{client: client, model: opts.Model}, nil
}

func (p *ollamaProvider) Diagnose(ctx context.Context, report string) (Diagnosis, error) {
	response, err := llms.GenerateFromSinglePrompt(ctx, p.client, BuildPrompt(report),
		llms.WithTemperature(0.1),
	)
	if err != nil {
		return Diagnosis{}, fmt.Errorf("ollama diagnosis failed (model=%s): %w", p.model, err)
	}
	return ParseDiagnosis(response), nil
}
