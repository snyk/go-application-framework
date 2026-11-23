package app

import (
	"errors"
	"io"
	"io/fs"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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

	_, storageErr := configuration.DefaultStorageDir()
	assert.Error(t, storageErr, "the default storage directory is unavailable without a home directory")
	assert.Empty(t, config.GetString(profile.DirKey), "no default profile directory is set, so none is relative")

	// Profiles fail closed: the registry is not built without a profile directory, and the error is the catalog error
	// SNYK-CLI-0036, asserted on its code rather than its text.
	_, err := workflow.GetProfileRegistry(engine)
	require.Error(t, err, "profiles are unavailable without a default profile directory")
	var snykErr snyk_errors.Error
	require.True(t, errors.As(err, &snykErr), "expected a catalog error, got %v", err)
	assert.Equal(t, "SNYK-CLI-0036", snykErr.ErrorCode)

	// The cache directory falls back to the relative path snyk/snyk-cli when neither the home nor the temp directory
	// is usable. That is intentional for restricted platforms and CI runners where only the workspace is writable, and
	// it is not a trust boundary because cached binaries are verified by checksum. So the cache path is allowed, and
	// anything else created in the working directory (profile files or directories) is a failure.
	cachePath := filepath.Join("snyk", "snyk-cli")
	var unexpected []string
	walkErr := filepath.WalkDir(cwd, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(cwd, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." || rel == "snyk" || rel == cachePath || strings.HasPrefix(rel, cachePath+string(filepath.Separator)) {
			return nil
		}
		unexpected = append(unexpected, rel)
		return nil
	})
	require.NoError(t, walkErr)
	assert.Empty(t, unexpected, "no profile file or directory is created in the working directory")
}
