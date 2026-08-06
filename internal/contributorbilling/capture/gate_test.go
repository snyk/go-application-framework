package capture_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestIsBillableCommand(t *testing.T) {
	assert.True(t, capture.IsBillableCommand("monitor"))
	assert.True(t, capture.IsBillableCommand("iac test --report"))
	assert.False(t, capture.IsBillableCommand("test"))
	assert.False(t, capture.IsBillableCommand("iac test"))
}

func TestCommandNameFromRawArgs(t *testing.T) {
	assert.Equal(t, "monitor", capture.CommandNameFromRawArgs([]string{"monitor"}))
	assert.Equal(t, "iac test --report", capture.CommandNameFromRawArgs([]string{"iac", "test", "--report"}))
	assert.Equal(t, "iac test", capture.CommandNameFromRawArgs([]string{"iac", "test"}))
}

func TestEnsureCaptureSessionForConfig_skipsWhenCommandNotBillable(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	config := configuration.NewWithOpts()
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	assert.Nil(t, capture.EnsureCaptureSessionForConfig(config, "test"))
	assert.Nil(t, capture.ActiveCapture())
}

func TestEnsureCaptureSessionForConfig_opensForBillableMonitor(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	config := configuration.NewWithOpts()
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	require.NotNil(t, capture.EnsureCaptureSessionForConfig(config, "monitor"))
	require.NotNil(t, capture.ActiveCapture())
}
