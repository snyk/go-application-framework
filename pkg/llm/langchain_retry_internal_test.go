package llm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmc/langchaingo/llms"
)

// seqLLM returns a scripted sequence of (resp, err) pairs across successive
// GenerateContent calls and records how many times it was called. Once the
// script is exhausted it keeps returning the final entry.
type seqLLM struct {
	results []seqResult
	calls   int
}

type seqResult struct {
	resp *llms.ContentResponse
	err  error
}

func (s *seqLLM) GenerateContent(_ context.Context, _ []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	i := s.calls
	s.calls++
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	r := s.results[i]
	return r.resp, r.err
}

func (s *seqLLM) Call(_ context.Context, _ string, _ ...llms.CallOption) (string, error) {
	return "", nil
}

func okResp() *llms.ContentResponse {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{StopReason: "stop"}}}
}

// errRateLimit mimics the langchaingo anthropic error text for a 429.
var errRateLimit = errors.New("anthropic: failed to create message: API returned unexpected status code: 429: rate limit exceeded")

func newTestAdapter(model llms.Model, maxRetries int) (*LangchainAdapter, *int) {
	sleeps := 0
	a := NewLangchainAdapter("anthropic", model)
	a.maxRetries = maxRetries
	a.sleep = func(_ context.Context, _ time.Duration) error {
		sleeps++
		return nil
	}
	return a, &sleeps
}

func TestRetryDelay_ExponentialThenCapped(t *testing.T) {
	assert.Equal(t, 2*time.Second, retryDelay(0))
	assert.Equal(t, 4*time.Second, retryDelay(1))
	assert.Equal(t, 8*time.Second, retryDelay(2))
	assert.Equal(t, 16*time.Second, retryDelay(3))
	assert.Equal(t, retryMaxDelay, retryDelay(4))  // 32s -> capped at 30s
	assert.Equal(t, retryMaxDelay, retryDelay(60)) // shift overflow -> capped
}

func TestIsRetryableError(t *testing.T) {
	assert.True(t, isRetryableError(errRateLimit))
	assert.True(t, isRetryableError(errors.New("API returned unexpected status code: 529: overloaded")))
	assert.True(t, isRetryableError(errors.New("429 Too Many Requests")))
	// Vertex/Gemini genai SDK spells a 429 as RESOURCE_EXHAUSTED — both the
	// REST APIError form (underscore) and the gRPC status form (no underscore).
	assert.True(t, isRetryableError(errors.New(`vertex: generate content: Error 429, Status: "RESOURCE_EXHAUSTED"`)))
	assert.True(t, isRetryableError(errors.New("vertex: generate content: rpc error: code = ResourceExhausted desc = Quota exceeded")))
	assert.False(t, isRetryableError(errors.New("status code: 400: bad request")))
	assert.False(t, isRetryableError(errors.New("status code: 401: unauthorized")))
	assert.False(t, isRetryableError(nil))
}

func TestGenerateWithRetry_RetriesOwnTimeout(t *testing.T) {
	// A per-call deadline (generateOnce's timeout) on a still-live caller
	// context is a transient stall and must be retried, like a 429.
	model := &seqLLM{results: []seqResult{
		{err: context.DeadlineExceeded},
		{resp: okResp()},
	}}
	a, sleeps := newTestAdapter(model, 5)

	resp, err := a.generateWithRetry(context.Background(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 2, model.calls)
	assert.Equal(t, 1, *sleeps)
}

func TestGenerateWithRetry_DoesNotRetryCallerCancel(t *testing.T) {
	// When the caller's context is cancelled, a DeadlineExceeded is the
	// caller's deadline, not ours — do not retry.
	model := &seqLLM{results: []seqResult{{err: context.DeadlineExceeded}}}
	a, sleeps := newTestAdapter(model, 5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.generateWithRetry(ctx, nil, nil)
	require.Error(t, err)
	assert.Equal(t, 1, model.calls)
	assert.Equal(t, 0, *sleeps)
}

func TestGenerateWithRetry_RetriesThenSucceeds(t *testing.T) {
	model := &seqLLM{results: []seqResult{
		{err: errRateLimit},
		{err: errRateLimit},
		{resp: okResp()},
	}}
	a, sleeps := newTestAdapter(model, 5)

	resp, err := a.generateWithRetry(context.Background(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 3, model.calls)
	assert.Equal(t, 2, *sleeps)
}

func TestGenerateWithRetry_NonRetryableDoesNotRetry(t *testing.T) {
	model := &seqLLM{results: []seqResult{
		{err: errors.New("status code: 400: bad request")},
	}}
	a, sleeps := newTestAdapter(model, 5)

	_, err := a.generateWithRetry(context.Background(), nil, nil)
	require.Error(t, err)
	assert.Equal(t, 1, model.calls)
	assert.Equal(t, 0, *sleeps)
}

func TestGenerateWithRetry_ExhaustsRetries(t *testing.T) {
	model := &seqLLM{results: []seqResult{{err: errRateLimit}}}
	a, sleeps := newTestAdapter(model, 3)

	_, err := a.generateWithRetry(context.Background(), nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errRateLimit)
	assert.Equal(t, 4, model.calls) // initial + 3 retries
	assert.Equal(t, 3, *sleeps)
}

func TestGenerateWithRetry_StopsOnContextCancel(t *testing.T) {
	model := &seqLLM{results: []seqResult{{err: errRateLimit}}}
	a := NewLangchainAdapter("anthropic", model)
	a.maxRetries = 5
	a.sleep = func(_ context.Context, _ time.Duration) error {
		return context.Canceled
	}

	_, err := a.generateWithRetry(context.Background(), nil, nil)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, model.calls) // gave up after the first sleep was cancelled
}
