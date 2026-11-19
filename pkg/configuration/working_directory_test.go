package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file pin CLI-1124: the working directory is never a source of configuration, and a home directory
// that cannot be determined does not move configuration into the working directory. A snyk.json committed to a
// repository must not set api, org or endpoint for whoever scans it.

// workingDirSnykJSON is what a repository could ship in its working directory.
const workingDirSnykJSON = `{"api":"https://attacker.example","org":"attacker-org","endpoint":"https://attacker.example","arbitrary_key":"attacker"}`

// isolateWorkingDir makes dir the working directory of the test and writes content as its snyk.json.
func isolateWorkingDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snyk.json"), []byte(content), 0o644))
	return dir
}

// Test_WorkingDirectorySnykJSON_IsNotRead checks that a snyk.json only in the working directory sets none of its keys,
// when there is no configstore file.
func Test_WorkingDirectorySnykJSON_IsNotRead(t *testing.T) {
	isolateHome(t)
	isolateWorkingDir(t, workingDirSnykJSON)

	c := NewWithOpts(WithFiles("snyk"))
	for _, key := range []string{"api", "org", "endpoint", "arbitrary_key"} {
		assert.Empty(t, c.GetString(key), "key %q must not come from the working directory", key)
	}
}

// Test_ConfigstoreWinsOverWorkingDirectorySnykJSON checks that with a configstore snyk.json and a working-directory
// snyk.json, the configstore file is used and no value from the working directory appears, including keys that the
// configstore file does not set.
func Test_ConfigstoreWinsOverWorkingDirectorySnykJSON(t *testing.T) {
	isolateHome(t)
	require.NoError(t, os.MkdirAll(determineBasePath(), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(determineBasePath(), "snyk.json"), []byte(`{"org":"store-org"}`), 0o600))
	isolateWorkingDir(t, workingDirSnykJSON)

	c := NewWithOpts(WithFiles("snyk"))
	assert.Equal(t, "store-org", c.GetString("org"))
	for _, key := range []string{"api", "endpoint", "arbitrary_key"} {
		assert.Empty(t, c.GetString(key), "key %q must not come from the working directory", key)
	}
}

// Test_HomeDirectoryUnknown_NothingIsReadOrWrittenInWorkingDirectory checks that when the home directory cannot be
// determined, the configuration is in memory without file storage: the working-directory snyk.json is not read, not
// written and not created over, and the default storage directory is not the working directory.
func Test_HomeDirectoryUnknown_NothingIsReadOrWrittenInWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	// os.UserHomeDir fails on an empty HOME (unix) or USERPROFILE (windows).
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	dir := isolateWorkingDir(t, workingDirSnykJSON)
	snykJSON := filepath.Join(dir, "snyk.json")

	c := NewWithOpts(WithFiles("snyk"))
	assert.Empty(t, c.GetString("org"), "the working directory file is not read")
	assert.Nil(t, c.GetStorage(), "there is no file storage without a home directory")

	c.PersistInStorage("org")
	c.Set("org", "written-by-cli")
	_, err := CreateConfigurationFile("snyk.json")
	assert.Error(t, err, "no configuration file is created without a home directory")

	content, err := os.ReadFile(snykJSON)
	require.NoError(t, err)
	assert.JSONEq(t, workingDirSnykJSON, string(content), "the working directory file is neither written nor truncated")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no other file is created in the working directory")

	assert.Empty(t, DefaultStorageDir(), "an unknown home directory is not reported as the working directory")
}
