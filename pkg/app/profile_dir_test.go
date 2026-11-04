package app

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// profileDirTestKey is a key that the profiles of these tests persist.
const profileDirTestKey = "profile_dir_test_key"

// newProfileDirTestEngine returns an application engine on config, and the home directory it was created with, which is
// a temporary directory.
func newProfileDirTestEngine(t *testing.T, config configuration.Configuration) (workflow.Engine, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	engine := CreateAppEngineWithOptions(WithConfiguration(config), WithLogger(log.New(io.Discard, "", 0)))
	require.NoError(t, engine.Init())
	return engine, home
}

// Test_ProfileDir_DefaultIsSnykProfilesInTheDefaultStorageDir checks that an application engine reads the profiles from
// snyk_profiles in the default storage directory, that reading a missing profile creates nothing there, and that a value
// persisted by a profile is written to <that directory>/<name>.json.
func Test_ProfileDir_DefaultIsSnykProfilesInTheDefaultStorageDir(t *testing.T) {
	configtest.IsolateEnvironmentForTest(t, "SNYK_CONFIG_PROFILE_DIR")
	config := configuration.NewInMemory()
	config.PersistInStorage(profileDirTestKey)
	engine, home := newProfileDirTestEngine(t, config)
	defaultDir := filepath.Join(home, ".config", "configstore", "snyk_profiles")
	assert.Equal(t, defaultDir, config.GetString(profile.DirKey))

	registry, err := workflow.GetProfileRegistry(engine)
	require.NoError(t, err)
	p, err := registry.Profile("x")
	require.NoError(t, err)
	assert.Equal(t, defaultDir, p.Configuration().GetString(profile.DirKey), "a profile derives the default too")
	assert.Empty(t, p.Configuration().GetString(profileDirTestKey), "a missing profile is empty")
	_, statErr := os.Stat(defaultDir)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "reading must not create the default profile directory")

	p.Configuration().Set(profileDirTestKey, "written")
	content, err := os.ReadFile(filepath.Join(defaultDir, "x.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"profile_dir_test_key":"written"}`, string(content))
}

// Test_ProfileDir_ExplicitValueOverridesTheDefault checks that a profile directory set on the configuration, or in the
// environment, wins over the default, and that the default directory is not created.
func Test_ProfileDir_ExplicitValueOverridesTheDefault(t *testing.T) {
	tests := []struct {
		name  string
		isSet bool // true sets the directory on the configuration, false in the environment
	}{
		{name: "set_on_the_configuration", isSet: true},
		{name: "environment_variable", isSet: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configtest.IsolateEnvironmentForTest(t, "SNYK_CONFIG_PROFILE_DIR")
			explicit := t.TempDir()
			config := configuration.NewInMemory()
			if tc.isSet {
				config.Set(profile.DirKey, explicit)
			} else {
				// GAF reads no SNYK_ variable by itself: an application maps the variable to the key
				config.AddAlternativeKeys(profile.DirKey, []string{"SNYK_CONFIG_PROFILE_DIR"})
				t.Setenv("SNYK_CONFIG_PROFILE_DIR", explicit)
			}
			config.PersistInStorage(profileDirTestKey)
			engine, home := newProfileDirTestEngine(t, config)

			assert.Equal(t, explicit, config.GetString(profile.DirKey))
			registry, err := workflow.GetProfileRegistry(engine)
			require.NoError(t, err)
			p, err := registry.Profile("x")
			require.NoError(t, err)
			p.Configuration().Set(profileDirTestKey, "explicit")

			assert.FileExists(t, filepath.Join(explicit, "x.json"))
			_, statErr := os.Stat(filepath.Join(home, ".config", "configstore", "snyk_profiles"))
			assert.ErrorIs(t, statErr, os.ErrNotExist, "the default directory must not be used")
		})
	}
}
