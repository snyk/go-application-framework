package contributorbilling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/contributorbilling"
)

func TestWait_NoPendingReturnsImmediately(t *testing.T) {
	start := time.Now()
	contributorbilling.Wait()
	assert.Less(t, time.Since(start), 50*time.Millisecond)
}

func TestWaitWithTimeout_WaitsForInFlightEmit(t *testing.T) {
	blockPost := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockPost
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resultCh := make(chan contributorbilling.Result, 1)
	contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{TargetID: "project-1"},
		},
		OnResult: func(result contributorbilling.Result) {
			resultCh <- result
		},
	})

	waitDone := make(chan bool, 1)
	go func() {
		waitDone <- contributorbilling.WaitWithTimeout(2 * time.Second)
	}()

	select {
	case <-waitDone:
		t.Fatal("WaitWithTimeout returned before POST completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(blockPost)

	select {
	case ok := <-waitDone:
		require.True(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for WaitWithTimeout")
	}

	result := waitForResult(t, resultCh)
	assert.Equal(t, contributorbilling.ResultStatusEmitted, result.Status)
}

func TestWaitWithTimeout_TimesOut(t *testing.T) {
	blockPost := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockPost
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	contributorbilling.EmitContributorBilling(context.Background(), contributorbilling.EmitOptions{
		HTTPClient: server.Client(),
		IngestURL:  server.URL,
		Capability: contributorbilling.CapabilityOSS,
		ScopeID:    "org-uuid",
		Items: []contributorbilling.BillingItem{
			{TargetID: "project-1"},
		},
	})

	ok := contributorbilling.WaitWithTimeout(50 * time.Millisecond)
	assert.False(t, ok)

	close(blockPost)
	contributorbilling.Wait()
}
