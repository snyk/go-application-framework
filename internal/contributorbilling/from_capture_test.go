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
	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestEmitFromCaptureFirstRecord_postsOnlyFirstProject(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)

	emitter := contributorbilling.NewEmitter()

	tmp := t.TempDir()
	t.Chdir(tmp)

	bag := capture.NewCapture()
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "22222222-2222-4222-8222-222222222222",
	})

	contributorbilling.EmitFromCaptureFirstRecord(context.Background(), bag, contributorbilling.FromCaptureOptions{
		Configuration: config,
		Emitter:       emitter,
		ScopeID:       "33333333-3333-4333-8333-333333333333",
		IngestURL:     server.URL,
	})

	require.True(t, emitter.WaitWithTimeout(2*time.Second))
	assert.Equal(t, 1, requestCount)
}

func TestEmitFromCapture_postsCapturedProjects(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)

	emitter := contributorbilling.NewEmitter()

	// Avoid scanning the go-application-framework git checkout during contributor collection.
	tmp := t.TempDir()
	t.Chdir(tmp)

	bag := capture.NewCapture()
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})

	contributorbilling.EmitFromCapture(context.Background(), bag, contributorbilling.FromCaptureOptions{
		Configuration: config,
		Emitter:       emitter,
		ScopeID:       "22222222-2222-4222-8222-222222222222",
		IngestURL:     server.URL,
	})

	require.True(t, emitter.WaitWithTimeout(2*time.Second))
	assert.Equal(t, 1, requestCount)
}

func TestEmitFromCapture_skipsEmptyScopeID(t *testing.T) {
	t.Parallel()

	emitter := contributorbilling.NewEmitter()
	bag := capture.NewCapture()
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})

	contributorbilling.EmitFromCapture(context.Background(), bag, contributorbilling.FromCaptureOptions{
		Emitter: emitter,
		ScopeID: "   ",
	})

	assert.True(t, emitter.WaitWithTimeout(50*time.Millisecond))
}
