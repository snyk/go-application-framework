package app_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// isolateUserScope points the user-scoped shared file at a temp directory and returns its path.
// The machine-wide location is a fixed OS path outside the test's control except on Windows, where
// ProgramData is pointed below a regular file so the machine-wide directory can never be created
// and every OS writes to the returned per-user path.
func isolateUserScope(t *testing.T) (sharedFilePath string) {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	notADirectory := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(notADirectory, nil, 0o600))
	t.Setenv("ProgramData", notADirectory)
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)
	if runtime.GOOS == "windows" {
		return filepath.Join(localAppData, "Snyk", "machine-id.json")
	}
	return filepath.Join(home, ".snyk", "machine-id.json")
}

func newAppEngine(opts ...app.Opts) workflow.Engine {
	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	return app.CreateAppEngineWithOptions(append([]app.Opts{app.WithConfiguration(config)}, opts...)...)
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var content map[string]any
	require.NoError(t, json.Unmarshal(data, &content))
	return content
}

func TestAcceptance_ViaAppEngineExplicitMachineIDIsReturnedButNotStored(t *testing.T) {
	sharedFilePath := isolateUserScope(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "app-wiring-test-machine-id")
	engine := newAppEngine(app.WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("x"), runtimeinfo.WithVersion("1.0.0"))))

	id, err := engine.GetRuntimeInfo().GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "app-wiring-test-machine-id", id)
	require.NoFileExists(t, sharedFilePath)
}

func TestAcceptance_ViaAppEngineGeneratedMachineIDIsStableAcrossRuns(t *testing.T) {
	sharedFilePath := isolateUserScope(t)

	first, err := newAppEngine().GetConfiguration().GetStringWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	second, err := newAppEngine().GetConfiguration().GetStringWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.NotEmpty(t, first)
	require.Equal(t, first, second)
	require.Equal(t, first, readJSON(t, sharedFilePath)["machine_id"])
}

func TestAcceptance_ViaAppEngineNoStorableMachineIDGivesErrNoMachineID(t *testing.T) {
	sharedFilePath := isolateUserScope(t)
	// The user-scoped directory cannot be created while a file occupies its path.
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Dir(sharedFilePath)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Dir(sharedFilePath), []byte("not a directory"), 0o600))
	engine := newAppEngine(app.WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("x"), runtimeinfo.WithVersion("1.0.0"))))

	_, err := engine.GetRuntimeInfo().GetMachineID()

	require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
}

func TestAcceptance_ViaAppEngineLogsMachineIDResolutionForSupportBundles(t *testing.T) {
	isolateUserScope(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "app-wiring-test-machine-id")
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	engine := newAppEngine(app.WithZeroLogger(&logger))

	_, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.Contains(t, logs.String(), "machine id: adopting value from external channel", "the app wiring must pass its logger into machine id resolution")
}

func TestAcceptance_ViaAppEngineSharedFileRecordsTheRuntimeInfoAsWriter(t *testing.T) {
	sharedFilePath := isolateUserScope(t)
	engine := newAppEngine(app.WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("snyk-ls"), runtimeinfo.WithVersion("9.9.9"))))

	_, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.Equal(t, "snyk-ls/9.9.9", readJSON(t, sharedFilePath)["writer"], "the engine's runtime info must reach the shared file write")
}
