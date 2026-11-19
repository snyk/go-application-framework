package app

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Test_HomeDirectoryUnknown_ProfilesAreNotInWorkingDirectory checks that when the home directory cannot be determined,
// the default profile directory is not a relative path, so a profile is never read from or written to the working
// directory (CLI-1124).
func Test_HomeDirectoryUnknown_ProfilesAreNotInWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	configtest.IsolateEnvironmentForTest(t, "SNYK_CONFIG_PROFILE_DIR")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	cwd := t.TempDir()
	t.Chdir(cwd)

	const profileKey = "profile_dir_test_key"
	config := configuration.NewInMemory()
	config.PersistInStorage(profileKey)
	engine := CreateAppEngineWithOptions(WithConfiguration(config), WithLogger(log.New(io.Discard, "", 0)))
	require.NoError(t, engine.Init())

	dir := config.GetString(profile.DirKey)
	assert.True(t, dir == "" || filepath.IsAbs(dir), "the profile directory must be empty or absolute, got %q", dir)

	// Whatever the registry does with an empty or relative directory, nothing may land in the working directory.
	if registry, err := workflow.GetProfileRegistry(engine); err == nil {
		if p, err := registry.Profile("x"); err == nil {
			p.Configuration().Set(profileKey, "written")
		}
	}
	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	assert.Empty(t, entries, "no profile file or directory is created in the working directory")
}
