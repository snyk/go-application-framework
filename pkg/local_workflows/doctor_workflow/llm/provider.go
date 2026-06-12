// Package llm is the provider seam for the Snyk Doctor diagnosis step
// (CLI-1577). The MVP adds a hosted Anthropic provider behind the same
// interface, and the seam itself is the input to the platform-wide LLM
// capability discussion (CLI-1571). Only Ollama (local/offline) is
// implemented for the spike.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	ProviderOllama = "ollama"

	defaultBaseURL = "http://localhost:11434"
)

// Diagnosis is the structured result rendered in the CLI's issue style.
// When the model response cannot be parsed as JSON, Raw carries the
// unstructured text and the other fields are empty.
type Diagnosis struct {
	Title        string   `json:"title"`
	RootCause    string   `json:"rootCause"`
	Evidence     []string `json:"evidence"`
	SuggestedFix Steps    `json:"suggestedFix"`
	Raw          string   `json:"-"`
}

// Steps tolerates models that return the fix as one string instead of the
// requested array.
type Steps []string

func (s *Steps) UnmarshalJSON(data []byte) error {
	var steps []string
	if err := json.Unmarshal(data, &steps); err == nil {
		*s = steps
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = Steps{single}
		return nil
	}
	return fmt.Errorf("suggestedFix is neither a string nor an array of strings")
}

// Provider produces a diagnosis from a rendered diagnostic report.
type Provider interface {
	Diagnose(ctx context.Context, report string) (Diagnosis, error)
}

type Options struct {
	Provider string
	BaseURL  string
	Model    string // required: no default, the model choice is the user's
}

func (o Options) withDefaults() Options {
	if o.Provider == "" {
		o.Provider = ProviderOllama
	}
	if o.BaseURL == "" {
		o.BaseURL = defaultBaseURL
	}
	return o
}

func NewProvider(opts Options) (Provider, error) {
	opts = opts.withDefaults()
	if opts.Model == "" {
		return nil, fmt.Errorf("no LLM model configured")
	}
	switch opts.Provider {
	case ProviderOllama:
		return newOllamaProvider(opts)
	default:
		return nil, fmt.Errorf("unsupported LLM provider %q (supported: %s)", opts.Provider, ProviderOllama)
	}
}
