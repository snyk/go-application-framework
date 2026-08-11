package contributorbilling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling"
)

func TestEmitter_WaitWithTimeout_IsolatedFromOtherEmitters(t *testing.T) {
	t.Parallel()

	blockPost := make(chan struct{})
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockPost
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(slowServer.Close)

	fastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(fastServer.Close)

	slow := contributorbilling.NewEmitter()
	fast := contributorbilling.NewEmitter()

	slow.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: slowServer.Client(),
		IngestURL:  slowServer.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
		},
	})

	ok := slow.WaitWithTimeout(50 * time.Millisecond)
	assert.False(t, ok)

	resultCh := make(chan contributorbilling.Result, 1)
	fast.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: fastServer.Client(),
		IngestURL:  fastServer.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Item: contributorbilling.BillingItem{
			EntityID: "project-2",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	require.True(t, fast.WaitWithTimeout(2*time.Second))

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)

	close(blockPost)
	slow.Wait()
}

func TestEmitter_RecoversFromPanicInOnResult(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	emitter := contributorbilling.NewEmitter()

	emitter.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Item: contributorbilling.BillingItem{
			EntityID: "project-1",
		},
		OnResult: func(result contributorbilling.Result) {
			panic("intentional panic in callback")
		},
	})

	// Should not hang; goroutine should recover from panic
	ok := emitter.WaitWithTimeout(2 * time.Second)
	assert.True(t, ok, "emitter should recover from OnResult panic and complete wait")

	// Subsequent emit should work normally
	resultCh := make(chan contributorbilling.Result, 1)
	emitter.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "11111111-1111-1111-1111-111111111111",
		Item: contributorbilling.BillingItem{
			EntityID: "project-2",
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	ok = emitter.WaitWithTimeout(2 * time.Second)
	assert.True(t, ok)
	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
}
