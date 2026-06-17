package doctor_workflow

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestDoctorWorkflowRegistration(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitDoctorWorkflow(engine)
	require.NoError(t, err)

	entry, ok := engine.GetWorkflow(WORKFLOWID_DOCTOR)
	assert.True(t, ok)
	require.NotNil(t, entry)

	flags := entry.GetConfigurationOptions()
	flagSet := workflow.FlagsetFromConfigurationOptions(flags)
	require.NotNil(t, flagSet)
	assert.NotNil(t, flagSet.Lookup(inputFlag))
	assert.NotNil(t, flagSet.Lookup(includeReportFlag))
	assert.NotNil(t, flagSet.Lookup(noLiveCheckFlag))
	assert.NotNil(t, flagSet.Lookup(configuration.FLAG_EXPERIMENTAL))
}

func setupMockContext(t *testing.T, config configuration.Configuration) *mocks.MockInvocationContext {
	t.Helper()
	logger := zerolog.Nop()
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	return invocationContextMock
}

func TestDoctorEntryPoint_ReadsInputFile(t *testing.T) {
	logContent := "hello debug log"
	logPath := filepath.Join(t.TempDir(), "debug.log")
	require.NoError(t, os.WriteFile(logPath, []byte(logContent), 0600))

	config := configuration.NewWithOpts()
	config.Set(inputFlag, logPath)

	output, err := doctorEntryPoint(setupMockContext(t, config), nil)
	require.NoError(t, err)
	require.Len(t, output, 1)

	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok)
	assert.Equal(t, logContent, string(payload))
	assert.Equal(t, "text/plain", output[0].GetContentType())
}

func TestDoctorEntryPoint_MissingInputFile(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(inputFlag, filepath.Join(t.TempDir(), "does-not-exist.log"))

	_, err := doctorEntryPoint(setupMockContext(t, config), nil)
	require.Error(t, err)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, "SNYK-CLI-0000", snykErr.ErrorCode)
}
