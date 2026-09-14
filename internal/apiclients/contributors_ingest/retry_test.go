package contributors_ingest

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

func TestClient_RetriesTransientFailures(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	require.NoError(t, postTo(t, server), "a transient failure must not lose the record")
	assert.Equal(t, int32(2), attempts.Load())
}

func TestClient_ExhaustsAttemptsInsideTheTimeout(t *testing.T) {
	server, attempts := serverAlwaysReturning(t, http.StatusServiceUnavailable)

	start := time.Now()
	err := postTo(t, server)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Equal(t, int32(requestAttempts), attempts.Load(), "every configured attempt must fit inside requestTimeout")
	assert.Less(t, elapsed, requestTimeout, "the client must give up on its own rather than be cut off by its deadline")
}

func TestClient_DoesNotRetryClientErrors(t *testing.T) {
	server, attempts := serverAlwaysReturning(t, http.StatusBadRequest)

	require.Error(t, postTo(t, server))
	assert.Equal(t, int32(1), attempts.Load(), "a rejected payload will be rejected again; retrying only wastes time")
}

func TestNewClient_LeavesTheCallersClientUntouched(t *testing.T) {
	transport := http.DefaultTransport
	shared := &http.Client{Transport: transport}

	_, err := NewClient(shared, "https://api.snyk.io", nil)
	require.NoError(t, err)

	assert.Same(t, transport, shared.Transport, "the caller's shared client must not be modified")
}

func TestRetrying_AddsRetryPolicy(t *testing.T) {
	logger := zerolog.Nop()

	for name, base := range map[string]*http.Client{
		"with a transport": {Transport: http.DefaultTransport},
		"without one":      {},
		"absent":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			client := retrying(base, &logger)
			require.NotNil(t, client)
			assert.IsType(t, &middleware.RetryMiddleware{}, client.Transport)
		})
	}
}

// serverAlwaysReturning counts requests and replies with status every time.
func serverAlwaysReturning(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)

	return server, &attempts
}

func postTo(t *testing.T, server *httptest.Server) error {
	t.Helper()

	client, err := NewClient(server.Client(), server.URL, nil)
	require.NoError(t, err)

	return client.SubmitContributors(
		t.Context(), uuid.New(), EntityTypeProject, "22222222-2222-2222-2222-222222222222", nil,
	)
}
