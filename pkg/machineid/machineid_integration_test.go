package machineid

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// TestIntegration_NoStorageResolvesWithoutPersisting exercises the nil-storage branch of
// mirrorIntoStorage: an in-memory configuration (no file behind it) must still resolve a valid
// value instead of erroring or panicking, matching TestNewInMemory_shouldNotBreakWhenTryingToPersist
// in pkg/configuration.
func TestIntegration_NoStorageResolvesWithoutPersisting(t *testing.T) {
	config := configuration.NewInMemory()
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	_, err = Validate(id)
	require.NoError(t, err)
}

// TestIntegration_EnsurePersistedForcesResolution exercises EnsurePersisted directly, for a
// consumer that never calls GetWithError on its own (for example a run that emits no analytics).
func TestIntegration_EnsurePersistedForcesResolution(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	id, err := EnsurePersisted(config)
	require.NoError(t, err)
	_, err = Validate(id)
	require.NoError(t, err)
	require.Equal(t, id, readSnykJSON(t)[configuration.MACHINE_ID])

	again, err := EnsurePersisted(config)
	require.NoError(t, err)
	require.Equal(t, id, again)
}

// TestIntegration_SeparateConfigurationsConvergeThroughSharedStorageFile is the acceptance
// concurrency scenario's stronger sibling: it uses two independent Configuration instances, each
// with its own JsonStorage and its own *flock.Flock backed by its own file descriptor, rather than
// clones sharing one Storage. This is what actually proves the shared config file (not just an
// in-process mutex) serializes two Snyk products racing to resolve on the same machine.
func TestIntegration_SeparateConfigurationsConvergeThroughSharedStorageFile(t *testing.T) {
	configtest.IsolateEnvironmentForTest(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	machineWideDir := filepath.Join(t.TempDir(), "machine-wide", "snyk")
	perUserDir := filepath.Join(t.TempDir(), "per-user", "snyk")
	sharedFilePaths = func() pathPair {
		return pathPair{
			machineWide: filepath.Join(machineWideDir, "machine-id.json"),
			perUser:     filepath.Join(perUserDir, "machine-id.json"),
		}
	}
	t.Cleanup(func() { sharedFilePaths = defaultSharedFilePaths })

	osMachineID = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { osMachineID = osidFallback })

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)

	const configs = 4
	results := make([]string, configs)
	var wg sync.WaitGroup
	wg.Add(configs)
	for i := 0; i < configs; i++ {
		go func(i int) {
			defer wg.Done()
			config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
			config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
			value, getErr := config.GetWithError(configuration.MACHINE_ID)
			require.NoError(t, getErr)
			id, ok := value.(string)
			require.True(t, ok)
			results[i] = id
		}(i)
	}
	wg.Wait()

	for i := 1; i < configs; i++ {
		require.Equal(t, results[0], results[i], "independent configurations must converge on the same machine id")
	}

	data, err := os.ReadFile(filepath.Join(home, ".config", "configstore", "snyk.json"))
	require.NoError(t, err)
	require.Contains(t, string(data), results[0])
}
