package machineid_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// TestAcceptance_ViaAppEngineProducesPersistedMachineID exercises the actual wiring in
// pkg/app.initConfiguration, proving CLI and language server consumers of a real engine share
// the same resolved and persisted machine identifier.
func TestAcceptance_ViaAppEngineProducesPersistedMachineID(t *testing.T) {
	configtest.IsolateEnvironmentForTest(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)

	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	engine := app.CreateAppEngineWithOptions(app.WithConfiguration(config))

	value, err := engine.GetConfiguration().GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.NotEmpty(t, id)

	data, err := os.ReadFile(filepath.Join(home, ".config", "configstore", "snyk.json"))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	require.Equal(t, id, m[configuration.MACHINE_ID])
}
