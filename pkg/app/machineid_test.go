package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func newAppEngine(t *testing.T, opts ...Opts) workflow.Engine {
	t.Helper()
	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)
	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	return CreateAppEngineWithOptions(append([]Opts{WithConfiguration(config)}, opts...)...)
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var content map[string]any
	require.NoError(t, json.Unmarshal(data, &content))
	return content
}

func TestAcceptance_ViaAppEngineSuppliedMachineIDIsReturnedButNotStored(t *testing.T) {
	opt := WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("x"), runtimeinfo.WithVersion("1.0.0")))
	for name, newEngine := range map[string]func(t *testing.T) workflow.Engine{
		"environment variable": func(t *testing.T) workflow.Engine {
			t.Helper()
			t.Setenv("INTERNAL_SNYK_MACHINE_ID", "app-wiring-test-machine-id")
			return newAppEngine(t, opt)
		},
		"set before the first read": func(t *testing.T) workflow.Engine {
			t.Helper()
			engine := newAppEngine(t, opt)
			engine.GetConfiguration().Set(configuration.MACHINE_ID, "app-wiring-test-machine-id")
			return engine
		},
	} {
		t.Run(name, func(t *testing.T) {
			sharedFilePath := isolateMachineIDStorage(t)
			engine := newEngine(t)

			id, err := engine.GetRuntimeInfo().GetMachineID()

			require.NoError(t, err)
			require.Equal(t, "app-wiring-test-machine-id", id)
			require.NoFileExists(t, sharedFilePath)
		})
	}
}

func TestAcceptance_ViaAppEngineNoStorableMachineIDGivesErrNoMachineID(t *testing.T) {
	sharedFilePath := isolateMachineIDStorage(t)
	// The user-scoped directory cannot be created while a file occupies its path.
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Dir(sharedFilePath)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Dir(sharedFilePath), []byte("not a directory"), 0o600))
	engine := newAppEngine(t, WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("x"), runtimeinfo.WithVersion("1.0.0"))))

	_, err := engine.GetRuntimeInfo().GetMachineID()

	require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
}

func TestAcceptance_ViaAppEngineLogsMachineIDResolutionForSupportBundles(t *testing.T) {
	isolateMachineIDStorage(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	engine := newAppEngine(t, WithZeroLogger(&logger))

	_, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.Contains(t, logs.String(), "machine id: no source produced a value, generating one", "the app wiring must pass its logger into machine id resolution")
}

func TestAcceptance_ViaAppEngineSharedFileRecordsTheRuntimeInfoAsWriter(t *testing.T) {
	sharedFilePath := isolateMachineIDStorage(t)
	engine := newAppEngine(t, WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("snyk-ls"), runtimeinfo.WithVersion("9.9.9"))))

	_, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.Equal(t, "snyk-ls/9.9.9", readJSON(t, sharedFilePath)["writer"], "the engine's runtime info must reach the shared file write")
}

func TestAcceptance_ViaAppEngineRuntimeInfoSetAfterCreationIsRecordedAsWriter(t *testing.T) {
	sharedFilePath := isolateMachineIDStorage(t)
	engine := newAppEngine(t)
	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("snyk-ls"), runtimeinfo.WithVersion("9.9.9")))

	_, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.Equal(t, "snyk-ls/9.9.9", readJSON(t, sharedFilePath)["writer"], "runtime info set after the engine was created must still reach the shared file write")
}

// Run with -race: a first MACHINE_ID lookup reads the engine's runtime info while it is still being set.
func TestAcceptance_ViaAppEngineLookupConcurrentWithSetRuntimeInfoDoesNotRace(t *testing.T) {
	isolateMachineIDStorage(t)
	engine := newAppEngine(t)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("snyk-ls"), runtimeinfo.WithVersion("9.9.9")))
	}()
	go func() {
		defer wg.Done()
		_, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
		assert.NoError(t, err)
	}()
	wg.Wait()
}

// makeUnreadable skips when permissions do not restrict this user, e.g. when running as root or on Windows.
func makeUnreadable(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) //nolint:errcheck // best-effort restore so t.TempDir can clean up
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("permissions do not restrict this user")
	}
}

func TestAcceptance_ViaAppEngineUnreadableSharedFileIsReportedWithTheMachineIDFoundAfterIt(t *testing.T) {
	sharedFilePath := isolateMachineIDStorage(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(sharedFilePath), 0o755))
	require.NoError(t, os.WriteFile(sharedFilePath, []byte(`{"machine_id":"shared-file-id"}`), 0o600))
	makeUnreadable(t, sharedFilePath)
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	studioFile := filepath.Join(home, ".snyk-studio", "device-id")
	require.NoError(t, os.MkdirAll(filepath.Dir(studioFile), 0o755))
	require.NoError(t, os.WriteFile(studioFile, []byte("studio-device-id"), 0o600))
	engine := newAppEngine(t, WithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("x"), runtimeinfo.WithVersion("1.0.0"))))

	id, err := engine.GetRuntimeInfo().GetMachineID()

	require.Equal(t, "studio-device-id", id)
	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr), "want an error catalog error, got %v", err)
	require.Equal(t, "SNYK-CLI-0030", catalogErr.ErrorCode)
	require.Equal(t, sharedFilePath, catalogErr.Meta["path"])
}
