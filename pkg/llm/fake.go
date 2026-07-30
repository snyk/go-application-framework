package llm

import "context"

// FakeProvider is a test double for Provider, useful to downstream packages
// that need to exercise the agent loop without a real LLM backend.
type FakeProvider struct {
	ProviderName string
	Err          error
	Responses    []*ChatResponse // consumed in order; last entry repeated when exhausted
	Requests     []*ChatRequest  // captured for assertions
	callCount    int
}

var _ Provider = (*FakeProvider)(nil)

func (f *FakeProvider) Name() string { return f.ProviderName }

func (f *FakeProvider) ChatCompletion(_ context.Context, req *ChatRequest) (*ChatResponse, error) {
	f.Requests = append(f.Requests, req)
	if f.Err != nil {
		return nil, f.Err
	}
	if len(f.Responses) == 0 {
		return &ChatResponse{StopReason: StopEndTurn}, nil
	}
	idx := f.callCount
	if idx >= len(f.Responses) {
		idx = len(f.Responses) - 1
	}
	f.callCount++
	return f.Responses[idx], nil
}
