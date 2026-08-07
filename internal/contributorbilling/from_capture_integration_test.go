package contributorbilling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/clibilling"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestCaptureMiddlewareToBillingEmit_integration(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var billingRequests int

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
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
	config.Set(configuration.API_URL, ingest.URL)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{registry.URL})
	config.Set(configuration.AUTHENTICATION_TOKEN, "token")
	config.Set(configuration.ORGANIZATION, "11111111-1111-1111-1111-111111111111")
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.RegisterWithEngine(engine)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	capture.ResetCommandSession()
	t.Cleanup(func() {
		capture.ResetCommandSession()
		clibilling.ResetPendingEmitForTest()
	})

	rt := middleware.NewContributorCaptureMiddleware(http.DefaultTransport, config, nil, func() string {
		return clibilling.ActiveCommand(engine)
	})

	req, err := http.NewRequest(http.MethodPut, registry.URL+"/v1/monitor/npm", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	require.True(t, capture.IsSessionSealed())
	assert.True(t, clibilling.FinishCommand(context.Background(), engine, config, true))
	assert.Equal(t, 1, billingRequests)
}

func TestCaptureMiddlewareToBillingEmit_waitsFromPostInvokeHook_integration(t *testing.T) {
	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var billingRequests int

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
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
	config.Set(configuration.API_URL, ingest.URL)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{registry.URL})
	config.Set(configuration.AUTHENTICATION_TOKEN, "token")
	config.Set(configuration.ORGANIZATION, "11111111-1111-1111-1111-111111111111")
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.RegisterWithEngine(engine)

	wfID := workflow.NewWorkflowIdentifier("main")
	flags := pflag.NewFlagSet("main", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		rt := middleware.NewContributorCaptureMiddleware(http.DefaultTransport, config, nil, func() string {
			return clibilling.ActiveCommand(engine)
		})
		req, reqErr := http.NewRequest(http.MethodPut, registry.URL+"/v1/monitor/npm", http.NoBody)
		if reqErr != nil {
			return nil, reqErr
		}
		res, roundTripErr := rt.RoundTrip(req)
		if roundTripErr != nil {
			return nil, roundTripErr
		}
		return nil, res.Body.Close()
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	capture.ResetCommandSession()
	t.Cleanup(func() {
		capture.ResetCommandSession()
		clibilling.ResetPendingEmitForTest()
	})

	_, err = engine.Invoke(wfID)
	require.NoError(t, err)
	assert.Nil(t, capture.ActiveCapture())
	assert.Equal(t, 1, billingRequests)
}
