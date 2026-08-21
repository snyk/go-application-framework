package clibilling_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/clibilling"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestContributorBillingPostInvokeHook_waitsForPendingEmit(t *testing.T) {
	resetCaptureSession(t)

	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var billingRequests int

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

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.RegisterWithEngine(engine)

	wfID := workflow.NewWorkflowIdentifier("main")
	flags := pflag.NewFlagSet("main", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		sessionBag := capture.ActiveCapture()
		require.NotNil(t, sessionBag)
		sessionBag.Add(capture.Record{
			Capability: capture.CapabilityOSS,
			EntityID:   projectID,
		})
		capture.SealAndNotifyFirstRecord()
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	capture.OpenCommandSession(".")
	_, err = engine.Invoke(wfID)
	require.NoError(t, err)

	assert.Nil(t, capture.ActiveCapture())
	assert.Equal(t, 1, billingRequests)
}

func TestContributorBillingPostInvokeHook_skipsAnalyticsReportWorkflow(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.RegisterWithEngine(engine)

	flags := pflag.NewFlagSet(localworkflows.WORKFLOWID_REPORT_ANALYTICS.Host, pflag.ContinueOnError)
	_, err := engine.Register(localworkflows.WORKFLOWID_REPORT_ANALYTICS, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	capture.OpenCommandSession(".")
	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})
	capture.SealAndNotifyFirstRecord()

	_, err = engine.Invoke(localworkflows.WORKFLOWID_REPORT_ANALYTICS)
	require.NoError(t, err)
	require.NotNil(t, capture.ActiveCapture(), "analytics hook should not clear the session")
}

func TestContributorBillingPostInvokeHook_skipsFilterFindingsWorkflow(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.RegisterWithEngine(engine)

	flags := pflag.NewFlagSet(localworkflows.FilterFindingsWorkflowName, pflag.ContinueOnError)
	_, err := engine.Register(localworkflows.WORKFLOWID_FILTER_FINDINGS, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	capture.OpenCommandSession(".")

	_, err = engine.Invoke(localworkflows.WORKFLOWID_FILTER_FINDINGS)
	require.NoError(t, err)
	require.NotNil(t, capture.ActiveCapture())
}

func TestTryEmitAfterFirstCapture_emitsFirstProjectOnly(t *testing.T) {
	resetCaptureSession(t)

	const (
		firstProjectID  = "11111111-1111-4111-8111-111111111111"
		secondProjectID = "22222222-2222-4222-8222-222222222222"
	)
	var billingRequests int

	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		billingRequests++
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(ingest.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, ingest.URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, "token")
	config.Set(configuration.ORGANIZATION, "33333333-3333-4333-8333-333333333333")
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := testEngine(t, config, "monitor")
	capture.OpenCommandSession(".")
	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	bag.Add(capture.Record{Capability: capture.CapabilityOSS, EntityID: firstProjectID})
	bag.Add(capture.Record{Capability: capture.CapabilityOSS, EntityID: secondProjectID})

	clibilling.TryEmitAfterFirstCapture(context.Background(), engine, config)
	assert.True(t, clibilling.FinishCommand(context.Background(), engine, config, true))
	assert.Equal(t, 1, billingRequests)
}

func TestEnableIfConfigured_registersPostInvokeHook(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.EnableIfConfigured(engine)

	wfID := workflow.NewWorkflowIdentifier("main")
	flags := pflag.NewFlagSet("main", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	_, err = engine.Invoke(wfID)
	require.NoError(t, err)
}

func TestFinishCommand_emitsCapturedBillingOnSuccess(t *testing.T) {
	resetCaptureSession(t)

	const projectID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	var billingRequests int

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
	capture.OpenCommandSession(".")
	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   projectID,
	})

	clibilling.TryEmitAfterFirstCapture(context.Background(), engine, config)
	assert.True(t, clibilling.FinishCommand(context.Background(), engine, config, true))
	assert.Nil(t, capture.ActiveCapture())
	assert.Equal(t, 1, billingRequests)
}

func TestTryEmitAfterFirstCapture_isIdempotent(t *testing.T) {
	resetCaptureSession(t)

	var billingRequests int
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
	capture.OpenCommandSession(".")
	bag := capture.ActiveCapture()
	require.NotNil(t, bag)
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	})

	clibilling.TryEmitAfterFirstCapture(context.Background(), engine, config)
	clibilling.TryEmitAfterFirstCapture(context.Background(), engine, config)
	assert.True(t, clibilling.FinishCommand(context.Background(), engine, config, true))
	assert.Equal(t, 1, billingRequests)
}

func TestContributorBillingPostInvokeHook_waitsWithinTimeout(t *testing.T) {
	resetCaptureSession(t)

	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(ingest.Close)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, ingest.URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, "token")
	config.Set(configuration.ORGANIZATION, "11111111-1111-1111-1111-111111111111")
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	clibilling.RegisterWithEngine(engine)

	wfID := workflow.NewWorkflowIdentifier("main")
	flags := pflag.NewFlagSet("main", pflag.ContinueOnError)
	_, err := engine.Register(wfID, workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		capture.OpenCommandSession(".")
		bag := capture.ActiveCapture()
		bag.Add(capture.Record{
			Capability: capture.CapabilityOSS,
			EntityID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		})
		clibilling.TryEmitAfterFirstCapture(context.Background(), engine, config)
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	engine.GetAnalytics().SetCommand("monitor")

	_, err = engine.Invoke(wfID)
	require.NoError(t, err)
	assert.Nil(t, capture.ActiveCapture())
}
