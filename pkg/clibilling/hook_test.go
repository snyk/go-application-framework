package clibilling_test

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
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestContributorBillingPostInvokeHook_discardsCaptureOnBillableWorkflowFailure(t *testing.T) {
	resetCaptureSession(t)
	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.AddPostInvokeHook(clibilling.ContributorBillingPostInvokeHook))

	wfID := workflow.NewWorkflowIdentifier("monitor")
	flags := pflag.NewFlagSet("monitor", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, assert.AnError
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))

	_, err = engine.Invoke(wfID)
	require.Error(t, err)
	assert.Nil(t, capture.ActiveCapture())
}

func TestContributorBillingPostInvokeHook_keepsCaptureOnBillableWorkflowSuccess(t *testing.T) {
	resetCaptureSession(t)
	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.AddPostInvokeHook(clibilling.ContributorBillingPostInvokeHook))

	wfID := workflow.NewWorkflowIdentifier("monitor")
	flags := pflag.NewFlagSet("monitor", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))

	_, err = engine.Invoke(wfID)
	require.NoError(t, err)
	require.NotNil(t, capture.ActiveCapture())
}

func TestContributorBillingPostInvokeHook_skipsFilterFindingsWorkflow(t *testing.T) {
	resetCaptureSession(t)
	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.AddPostInvokeHook(clibilling.ContributorBillingPostInvokeHook))

	flags := pflag.NewFlagSet(localworkflows.FilterFindingsWorkflowName, pflag.ContinueOnError)
	_, err := engine.Register(localworkflows.WORKFLOWID_FILTER_FINDINGS, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, assert.AnError
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))

	_, err = engine.Invoke(localworkflows.WORKFLOWID_FILTER_FINDINGS)
	require.Error(t, err)
	require.NotNil(t, capture.ActiveCapture(), "filter workflow failure should not discard capture; teardown owns finalize")
}

func TestFinishCommand_emitsCapturedBillingOnSuccess(t *testing.T) {
	resetCaptureSession(t)

	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var billingRequests int

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, writeErr := w.Write([]byte(`{"uri":"https://app.snyk.io/org/acme/project/` + projectID + `/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`))
		require.NoError(t, writeErr)
	}))
	t.Cleanup(registry.Close)

	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		billingRequests++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(ingest.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, ingest.URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, "token")
	config.Set(configuration.ORGANIZATION, "11111111-1111-1111-1111-111111111111")
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := testEngine(t, config, "monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))
	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   projectID,
	})

	assert.True(t, clibilling.FinishCommand(context.Background(), engine, config, true))
	assert.Nil(t, capture.ActiveCapture())
	assert.Equal(t, 1, billingRequests)
}

func TestEnableIfConfigured_registersPostInvokeHook(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.EnableIfConfigured(engine)

	wfID := workflow.NewWorkflowIdentifier("monitor")
	flags := pflag.NewFlagSet("monitor", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, assert.AnError
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))

	_, err = engine.Invoke(wfID)
	require.Error(t, err)
	assert.Nil(t, capture.ActiveCapture())
}
