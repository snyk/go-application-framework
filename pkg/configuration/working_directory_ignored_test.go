package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WorkingDirConfigFileWarning_ConfigstoreFileMissing(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.NotEmpty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_HomeDirectoryUnset(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.NotEmpty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_HomeDirectoryRelative(t *testing.T) {
	t.Setenv("HOME", "relative-home")
	t.Setenv("USERPROFILE", "relative-home")
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.NotEmpty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_ConfigstoreFileIsADirectory(t *testing.T) {
	isolateHome(t)
	require.NoError(t, os.MkdirAll(filepath.Join(setupConfigstoreDir(t), "snyk.json"), 0o755))
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.NotEmpty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_NoneWhenTheConfigstoreFileExists(t *testing.T) {
	isolateHome(t)
	writeSnykJSON(t, setupConfigstoreDir(t))
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_NoneWhenTheConfigstoreFileIsUnreadable(t *testing.T) {
	isolateHome(t)
	store := setupConfigstoreDir(t)
	writeSnykJSON(t, store)
	require.NoError(t, os.Chmod(filepath.Join(store, "snyk.json"), 0o000))
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_NoneWithoutAWorkingDirectoryFile(t *testing.T) {
	isolateHome(t)
	enterTempCWD(t)

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_NoneWhenTheWorkingDirectoryFileIsADirectory(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	require.NoError(t, os.Mkdir(filepath.Join(workingDir, "snyk.json"), 0o755))

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_NoneInTheConfigstoreDirectory(t *testing.T) {
	isolateHome(t)
	configStore := setupConfigstoreDir(t)
	writeSnykJSON(t, configStore)
	t.Chdir(configStore)

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig()))
}

func Test_WorkingDirConfigFileWarning_FollowsTheConfigurationFileName(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, "other.json"), []byte(workingDirSnykJSON), 0o644))

	assert.Contains(t, WorkingDirConfigFileWarning(NewWithOpts(WithFiles("other"))), filepath.Join(workingDir, "other.json"))
}

func Test_WorkingDirConfigFileWarning_NoneForAFileOfAnotherName(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.Empty(t, WorkingDirConfigFileWarning(NewWithOpts(WithFiles("other"))))
}

func Test_WorkingDirConfigFileWarning_ClonedConfiguration(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.NotEmpty(t, WorkingDirConfigFileWarning(snykConfig().Clone()))
}

func Test_WorkingDirConfigFileWarning_NoneForAClonedConfigurationWhenTheConfigstoreFileExists(t *testing.T) {
	isolateHome(t)
	writeSnykJSON(t, setupConfigstoreDir(t))
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig().Clone()))
}

func Test_WorkingDirConfigFileWarning_NoneForTheEmptyNameOfAClone(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	require.NoError(t, os.WriteFile(filepath.Join(workingDir, ".json"), []byte(workingDirSnykJSON), 0o644))

	assert.Empty(t, WorkingDirConfigFileWarning(snykConfig().Clone()))
}

func Test_WorkingDirConfigFileWarning_NoneForAPinnedConfiguration(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)
	pinned := NewWithOpts(WithPinnedFile(filepath.Join(t.TempDir(), "snyk.json")))

	assert.Empty(t, WorkingDirConfigFileWarning(pinned))
	assert.Empty(t, WorkingDirConfigFileWarning(pinned.Clone()))
}

func Test_WorkingDirConfigFileWarning_NoneForAnInMemoryConfiguration(t *testing.T) {
	isolateHome(t)
	workingDir := enterTempCWD(t)
	writeSnykJSON(t, workingDir)

	assert.Empty(t, WorkingDirConfigFileWarning(NewInMemory()))
}

func snykConfig() Configuration {
	return NewWithOpts(WithFiles("snyk"))
}

// enterTempCWD makes a new temporary directory the working directory and returns it as the operating system reports it,
// which can differ from t.TempDir on macOS.
func enterTempCWD(t *testing.T) string {
	t.Helper()
	t.Chdir(t.TempDir())
	dir, err := os.Getwd()
	require.NoError(t, err)
	return dir
}

func setupConfigstoreDir(t *testing.T) string {
	t.Helper()
	dir, err := basePath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	return dir
}

func writeSnykJSON(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snyk.json"), []byte(workingDirSnykJSON), 0o644))
}
