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
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/clibilling"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
)

func TestCaptureMiddlewareToEmitFromCapture_integration(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var billingRequests int

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
		require.NoError(t, err)
	}))
	t.Cleanup(registry.Close)

	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		billingRequests++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(ingest.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, registry.URL)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{registry.URL})
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(config))
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	rt := middleware.NewContributorCaptureMiddleware(http.DefaultTransport, config, nil, func() string {
		return clibilling.ActiveCommand(engine)
	})

	req, err := http.NewRequest(http.MethodPut, registry.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	bag := capture.ActiveCapture()
	require.NotNil(t, bag)

	emitter := contributorbilling.NewEmitter()
	contributorbilling.EmitFromCapture(context.Background(), bag, contributorbilling.FromCaptureOptions{
		Configuration: config,
		Engine:        engine,
		Emitter:       emitter,
		ScopeID:       "11111111-1111-1111-1111-111111111111",
		IngestURL:     ingest.URL,
	})

	require.True(t, emitter.WaitWithTimeout(2*time.Second))
	assert.Equal(t, 1, billingRequests)
}
