package clibilling_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/clibilling"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func resetCaptureSession(t *testing.T) {
	t.Helper()
	capture.ResetCommandSession()
	clibilling.ResetPendingEmitForTest()
	t.Cleanup(func() {
		capture.ResetCommandSession()
		clibilling.ResetPendingEmitForTest()
	})
}

func testEngine(t *testing.T, config configuration.Configuration, command string) workflow.Engine {
	t.Helper()

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.SetConfiguration(config)
	require.NoError(t, engine.Init())
	if command != "" {
		engine.GetAnalytics().SetCommand(command)
	}
	return engine
}

func TestEnableIfConfigured_returnsSameEngine(t *testing.T) {
	base := workflow.NewDefaultWorkFlowEngine()
	engine := clibilling.EnableIfConfigured(base)
	assert.Same(t, base, engine)
}

func TestDefaultRepoPath(t *testing.T) {
	assert.Equal(t, ".", clibilling.DefaultRepoPath(""))
	assert.Equal(t, "/tmp/repo", clibilling.DefaultRepoPath("/tmp/repo"))
}

func TestIsBillableCommand(t *testing.T) {
	assert.True(t, clibilling.IsBillableCommand("monitor"))
	assert.True(t, clibilling.IsBillableCommand("iac test --report"))
	assert.False(t, clibilling.IsBillableCommand("test"))
	assert.False(t, clibilling.IsBillableCommand("iac test"))
}

func TestEnsureCaptureSession_noOpWhenCaptureDisabled(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	engine := testEngine(t, config, "monitor")
	assert.Nil(t, clibilling.EnsureCaptureSession(engine))
}

func TestEnsureCaptureSession_opensSessionForBillableMonitor(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)
	engine := testEngine(t, config, "monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))
	require.NotNil(t, capture.ActiveCapture())
}

func TestEnsureCaptureSession_skipsNonBillableCommand(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)
	engine := testEngine(t, config, "test")

	assert.Nil(t, clibilling.EnsureCaptureSession(engine))
	assert.Nil(t, capture.ActiveCapture())
}

func TestFinishCommand_closesActiveSession(t *testing.T) {
	resetCaptureSession(t)

	config := configuration.NewWithOpts()
	config.Set(clibilling.ConfigurationKeyCaptureEnabled, true)
	engine := testEngine(t, config, "monitor")

	require.NotNil(t, clibilling.EnsureCaptureSession(engine))
	require.NotNil(t, capture.ActiveCapture())

	assert.True(t, clibilling.FinishCommand(context.Background(), engine, config, true))
	assert.Nil(t, capture.ActiveCapture())
}
