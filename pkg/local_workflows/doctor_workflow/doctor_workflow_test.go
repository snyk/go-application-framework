package doctor_workflow

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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
	assert.NotNil(t, flagSet.Lookup(noLiveCheckFlag))
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
	assert.Equal(t, ok, true)
	rendered := string(payload)
	assert.Contains(t, rendered, "Notable Events")
	assert.Contains(t, rendered, "401 Unauthorized")
	assert.Contains(t, rendered, "Exit Code:")
}

func Test_runDoctor_readsPipedStdin(t *testing.T) {
	config := configuration.NewWithOpts()

	output, err := runDoctor(setupMockContext(t, config), strings.NewReader(sampleLog), false)
	require.NoError(t, err)
	require.Len(t, output, 1)
	payload, ok := output[0].GetPayload().([]byte)
	assert.Equal(t, ok, true)
	rendered := string(payload)
	assert.Contains(t, rendered, "Notable Events")
}

func Test_runDoctor_noInputOnTerminalErrors(t *testing.T) {
	config := configuration.NewWithOpts()

	_, err := runDoctor(setupMockContext(t, config), strings.NewReader(""), true)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
}

func Test_runDoctor_missingInputFile(t *testing.T) {
	config := configuration.NewWithOpts()
	config.Set(inputFlag, filepath.Join(t.TempDir(), "does-not-exist.log"))

	_, err := runDoctor(setupMockContext(t, config), strings.NewReader(""), false)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, "SNYK-CLI-0000", snykErr.ErrorCode)
}

func Test_readDebugLog(t *testing.T) {
	tests := []struct {
		name     string
		fileBody *string
		stdin    *string
		expected string
		wantErr  bool
	}{
		{name: "reads from input file", fileBody: new("hello from file"), expected: "hello from file"},
		{name: "reads empty input file", fileBody: new("")},
		{name: "reads from STDIN when no input path", stdin: new("hello from stdin"), expected: "hello from stdin"},
		{name: "reads empty STDIN", stdin: new("")},
		{name: "errors when input file does not exist", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				inputPath string
				stdin     io.Reader
			)
			switch {
			case tt.fileBody != nil:
				inputPath = filepath.Join(t.TempDir(), "debug.log")
				require.NoError(t, os.WriteFile(inputPath, []byte(*tt.fileBody), 0600))
			case tt.stdin != nil:
				stdin = strings.NewReader(*tt.stdin)
			default:
				inputPath = filepath.Join(t.TempDir(), "does-not-exist.log")
			}

			got, err := readDebugLog(stdin, inputPath)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}
