package doctor_workflow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	connectivitycheck "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const sampleLog = "2026-06-10T13:10:38Z main - < response [0x1]: 401 Unauthorized\n" +
	"2026-06-10T13:10:38Z main - ------------ Summary ------------\n" +
	"2026-06-10T13:10:38Z main - ------------ Errors ------------\n" +
	"2026-06-10T13:10:38Z main - Authentication error (SNYK-0005)\n" +
	"2026-06-10T13:10:38Z main - Exit Code:             2"

func Test_DoctorWorkflow_registration(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)

	require.NoError(t, InitDoctorWorkflow(engine))

	entry, ok := engine.GetWorkflow(WORKFLOWID_DOCTOR)
	assert.True(t, ok)
	require.NotNil(t, entry)

	flagSet := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
	require.NotNil(t, flagSet)
	assert.NotNil(t, flagSet.Lookup(inputFlag))
	assert.NotNil(t, flagSet.Lookup(liveFlag))
	assert.NotNil(t, flagSet.Lookup(jsonFlag))
}

func setupMockContext(t *testing.T, config configuration.Configuration) *mocks.MockInvocationContext {
	t.Helper()
	logger := zerolog.Nop()
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().Context().Return(context.Background()).AnyTimes()
	return invocationContextMock
}

func Test_runDoctor_summarizesInputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug.log")
	require.NoError(t, os.WriteFile(path, []byte(sampleLog), 0600))

	config := configuration.NewWithOpts()
	config.Set(inputFlag, path)

	output, err := runDoctor(setupMockContext(t, config), strings.NewReader(""), false)
	require.NoError(t, err)
	require.Len(t, output, 1)

	assert.Equal(t, "text/plain", output[0].GetContentType())
	payload, ok := output[0].GetPayload().([]byte)
	assert.True(t, ok)
	rendered := string(payload)
	assert.Contains(t, rendered, "Notable Events")
	assert.Contains(t, rendered, "401 Unauthorized")
	assert.Contains(t, rendered, "Exit Code:")
	assert.NotContains(t, rendered, "Connectivity")
}

func Test_runDoctor_readsPipedStdin(t *testing.T) {
	config := configuration.NewWithOpts()

	output, err := runDoctor(setupMockContext(t, config), strings.NewReader(sampleLog), false)
	require.NoError(t, err)
	require.Len(t, output, 1)
	payload, ok := output[0].GetPayload().([]byte)
	assert.True(t, ok)
	rendered := string(payload)
	assert.Contains(t, rendered, "Notable Events")
	assert.NotContains(t, rendered, "Connectivity")
}

func Test_runDoctor_gathersLiveContextWithLiveFlag(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(liveFlag, true)

	ctx := setupMockContext(t, config)
	engine := mocks.NewMockEngine(gomock.NewController(t))
	engine.EXPECT().
		Invoke(auth.WhoAmIWorkflowID, gomock.Any(), gomock.Any()).
		Return([]workflow.Data{whoAmIData("user@snyk.io")}, nil)
	engine.EXPECT().
		InvokeWithConfig(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, gomock.Any()).
		Return([]workflow.Data{connectivityData(sampleConnectivityJSON)}, nil)
	ctx.EXPECT().GetEngine().Return(engine).AnyTimes()

	output, err := runDoctor(ctx, strings.NewReader(sampleLog), false)
	require.NoError(t, err)
	require.Len(t, output, 1)

	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok)
	rendered := string(payload)
	assert.Contains(t, rendered, "Notable Events")
	assert.Contains(t, rendered, "Authentication")
	assert.Contains(t, rendered, "Authenticated as user@snyk.io")
	assert.Contains(t, rendered, "Connectivity")
	assert.Contains(t, rendered, "Hosts: 2/2 reachable")
}

func whoAmIData(payload string) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(auth.WhoAmIWorkflowID, "whoami"),
		"text/plain",
		payload,
	)
}

func Test_runDoctor_bareInvocationDefaultsToLive(t *testing.T) {
	config := configuration.NewWithOpts()

	ctx := setupMockContext(t, config)
	engine := mocks.NewMockEngine(gomock.NewController(t))
	engine.EXPECT().
		Invoke(auth.WhoAmIWorkflowID, gomock.Any(), gomock.Any()).
		Return([]workflow.Data{whoAmIData("user@snyk.io")}, nil)
	engine.EXPECT().
		InvokeWithConfig(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, gomock.Any()).
		Return([]workflow.Data{connectivityData(sampleConnectivityJSON)}, nil)
	ctx.EXPECT().GetEngine().Return(engine).AnyTimes()

	output, err := runDoctor(ctx, strings.NewReader(""), true)
	require.NoError(t, err)
	require.Len(t, output, 1)

	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok)
	rendered := string(payload)
	assert.Contains(t, rendered, "Authenticated as user@snyk.io")
	assert.Contains(t, rendered, "Hosts: 2/2 reachable")
}

func Test_runDoctor_continuesWhenConnectivityFails(t *testing.T) {
	config := configuration.NewWithOpts()

	ctx := setupMockContext(t, config)
	engine := mocks.NewMockEngine(gomock.NewController(t))
	engine.EXPECT().
		Invoke(auth.WhoAmIWorkflowID, gomock.Any(), gomock.Any()).
		Return([]workflow.Data{whoAmIData("user@snyk.io")}, nil)
	engine.EXPECT().
		InvokeWithConfig(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, gomock.Any()).
		Return(nil, assert.AnError)
	ctx.EXPECT().GetEngine().Return(engine).AnyTimes()

	output, err := runDoctor(ctx, strings.NewReader(""), true)
	require.NoError(t, err)

	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok)
	rendered := string(payload)
	assert.Contains(t, rendered, "Failed to run connectivity check")
}

const sampleConnectivityJSON = `{
  "proxyConfig": {"detected": false},
  "hostResults": [
    {"host": "api.snyk.io", "status": 0},
    {"host": "app.snyk.io", "status": 1}
  ],
  "todos": [],
  "organizations": [
    {"slug": "my-org", "isDefault": true}
  ],
  "tokenPresent": true
}`

func connectivityData(payload string) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, "connectivity-check"),
		"application/json",
		[]byte(payload),
	)
}

func Test_runDoctor_missingInputFile(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(inputFlag, filepath.Join(t.TempDir(), "does-not-exist.log"))

	_, err := runDoctor(setupMockContext(t, config), strings.NewReader(""), false)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, "SNYK-CLI-0000", snykErr.ErrorCode)
}

func Test_runDoctor_jsonOutput(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(jsonFlag, true)

	output, err := runDoctor(setupMockContext(t, config), strings.NewReader(sampleLog), false)
	require.NoError(t, err)
	require.Len(t, output, 1)

	assert.Equal(t, "application/json", output[0].GetContentType())
	payload, ok := output[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.Contains(t, string(payload), `"findings"`)
}
