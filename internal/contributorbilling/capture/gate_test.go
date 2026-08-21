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
	assert.True(t, capture.IsBillableCommand("aibom --upload"))
	assert.False(t, capture.IsBillableCommand("aibom"))
	assert.False(t, capture.IsBillableCommand("test"))
	assert.False(t, capture.IsBillableCommand("iac test"))
}

func TestCommandNameFromRawArgs(t *testing.T) {
	assert.Equal(t, "monitor", capture.CommandNameFromRawArgs([]string{"monitor"}))
	assert.Equal(t, "iac test --report", capture.CommandNameFromRawArgs([]string{"iac", "test", "--report"}))
	assert.Equal(t, "iac test", capture.CommandNameFromRawArgs([]string{"iac", "test"}))
	assert.Equal(t, "aibom --upload", capture.CommandNameFromRawArgs([]string{"aibom", ".", "--experimental", "--upload", "--repo", "python-chatbot"}))
	assert.Equal(t, "aibom", capture.CommandNameFromRawArgs([]string{"aibom", ".", "--experimental"}))
}

func TestResolveBillableCommand_prefersRawArgsReportFlag(t *testing.T) {
	raw := []string{"iac", "test", "--report", "."}
	assert.Equal(t, "iac test --report", capture.ResolveBillableCommand("iac test", raw))
	assert.True(t, capture.IsBillableCommand(capture.ResolveBillableCommand("iac test", raw)))

	raw = []string{"code", "test", "--report", "--project-name=x", "."}
	assert.Equal(t, "code test --report", capture.ResolveBillableCommand("code test", raw))

	assert.Equal(t, "monitor", capture.ResolveBillableCommand("monitor", []string{"monitor"}))
	assert.Equal(t, "test", capture.ResolveBillableCommand("test", []string{"test", "--report"}))
	assert.Equal(t, "aibom --upload", capture.ResolveBillableCommand("aibom", []string{"aibom", ".", "--upload"}))
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

func TestEnsureCaptureSessionForConfig_opensForBillableAIBOMUpload(t *testing.T) {
	capture.ResetCommandSession()
	t.Cleanup(func() { capture.ResetCommandSession() })

	config := configuration.NewWithOpts()
	config.Set(capture.ConfigurationKeyCaptureEnabled, true)

	require.NotNil(t, capture.EnsureCaptureSessionForConfig(config, "aibom --upload"))
	require.NotNil(t, capture.ActiveCapture())
}
