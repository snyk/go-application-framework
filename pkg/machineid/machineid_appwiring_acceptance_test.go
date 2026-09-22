package machineid_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// TestAcceptance_ViaAppEngineProducesPersistedMachineID exercises the actual wiring in
// pkg/app.initConfiguration, proving CLI and language server consumers of a real engine share
// the same resolved and persisted machine identifier.
//
// A real, pre-existing XDG_CONFIG_HOME is simulated (rather than left absent) because
// defaultSharedFilePaths prefers it over HOME on Linux: a developer running this suite locally
// typically has XDG_CONFIG_HOME set, and without isolating it this test would read and write that
// developer's real shared machine-id file instead of the temp one under home.
func TestAcceptance_ViaAppEngineProducesPersistedMachineID(t *testing.T) {
	leakedXDGConfigHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", leakedXDGConfigHome)
	configtest.IsolateEnvironmentForTest(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "app-wiring-test-machine-id")

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)

	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(config))

	value, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "app-wiring-test-machine-id", value)

	data, err := os.ReadFile(filepath.Join(home, ".config", "configstore", "snyk.json"))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	require.Equal(t, value, m[configuration.MACHINE_ID])

	entries, err := os.ReadDir(leakedXDGConfigHome)
	require.NoError(t, err)
	require.Empty(t, entries, "resolution must not write into a pre-existing XDG_CONFIG_HOME leaked from the developer's real environment")
}

// TestAcceptance_ViaAppEngineLogsMachineIDResolutionForSupportBundles proves the logger
// pkg/app.initConfiguration wires into every other default value function also reaches
// machineid.Resolve, so a support log bundle actually captures machine id resolution decisions.
func TestAcceptance_ViaAppEngineLogsMachineIDResolutionForSupportBundles(t *testing.T) {
	configtest.IsolateEnvironmentForTest(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "app-wiring-test-machine-id")

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)

	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(config), app.WithZeroLogger(&logger))

	_, err = engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.Contains(t, logs.String(), "machine id: adopting value from external channel", "the real app wiring must pass its logger into machineid.Resolve")
}
