package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolvedDir returns dir with its symlinks resolved, because the working directory reported by the operating system can
// differ from the path given to t.TempDir (for example /var and /private/var on macOS).
func resolvedDir(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	return resolved
}

// enterWorkingDirWithSnykJSON makes a new temporary directory the working directory of the test, with workingDirSnykJSON
// as its snyk.json, and returns the directory.
func enterWorkingDirWithSnykJSON(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snyk.json"), []byte(workingDirSnykJSON), 0o644))
	return dir
}

// writeConfigstoreSnykJSON writes the configstore snyk.json of the isolated home directory and returns its path.
func writeConfigstoreSnykJSON(t *testing.T) string {
	t.Helper()
	store, err := basePath()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(store, 0o755))
	file := filepath.Join(store, "snyk.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"org":"store-org"}`), 0o600))
	return file
}

// Test_IgnoredWorkingDirConfigFiles_ReportsTheWorkingDirectoryFile is the acceptance example of CLI-1124: a snyk.json only
// in the working directory, with no configstore file, is reported. It is not reported when the pinned file is that file.
func Test_IgnoredWorkingDirConfigFiles_ReportsTheWorkingDirectoryFile(t *testing.T) {
	isolateHome(t)
	dir := enterWorkingDirWithSnykJSON(t)
	want := filepath.Join(resolvedDir(t, dir), "snyk.json")

	assert.Equal(t, []string{want}, IgnoredWorkingDirConfigFiles("", "snyk"))
	assert.Empty(t, IgnoredWorkingDirConfigFiles(filepath.Join(dir, "snyk.json"), "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_AbsentFileIsNotReported(t *testing.T) {
	isolateHome(t)
	t.Chdir(t.TempDir())

	assert.Nil(t, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_EmptyFileListReportsNothing(t *testing.T) {
	isolateHome(t)
	enterWorkingDirWithSnykJSON(t)

	assert.Nil(t, IgnoredWorkingDirConfigFiles(""))
}

func Test_IgnoredWorkingDirConfigFiles_DirectoryIsNotReported(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "snyk.json"), 0o755))

	assert.Nil(t, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_SymlinkToConfigstoreFileIsNotReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on windows")
	}
	isolateHome(t)
	target := writeConfigstoreSnykJSON(t)
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "snyk.json")))

	assert.Nil(t, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_SymlinkToOtherRegularFileIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on windows")
	}
	isolateHome(t)
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	require.NoError(t, os.WriteFile(outside, []byte(workingDirSnykJSON), 0o644))
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "snyk.json")))

	// the entry in the working directory is what GAF ignores, so it is reported under its own path
	assert.Equal(t, []string{filepath.Join(resolvedDir(t, dir), "snyk.json")}, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_DanglingSymlinkIsNotReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs privileges on windows")
	}
	isolateHome(t)
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing.json"), filepath.Join(dir, "snyk.json")))

	assert.Nil(t, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_WorkingDirectoryIsConfigstoreDirectoryIsNotReported(t *testing.T) {
	isolateHome(t)
	writeConfigstoreSnykJSON(t)
	store, err := basePath()
	require.NoError(t, err)
	t.Chdir(store)

	assert.Nil(t, IgnoredWorkingDirConfigFiles("", "snyk"), "the configstore file is the file in use, not an ignored one")
}

func Test_IgnoredWorkingDirConfigFiles_ConfigstoreFilePresentWorkingDirectoryFileIsReported(t *testing.T) {
	isolateHome(t)
	writeConfigstoreSnykJSON(t)
	dir := enterWorkingDirWithSnykJSON(t)

	// the configstore file is in use and the working directory file is ignored, so the latter is reported
	assert.Equal(t, []string{filepath.Join(resolvedDir(t, dir), "snyk.json")}, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_PinnedFileOtherThanTheWorkingDirectoryFileIsReported(t *testing.T) {
	isolateHome(t)
	writeConfigstoreSnykJSON(t)
	dir := enterWorkingDirWithSnykJSON(t)
	pinned := filepath.Join(t.TempDir(), "profile.json")
	require.NoError(t, os.WriteFile(pinned, []byte(`{}`), 0o600))

	assert.Equal(t, []string{filepath.Join(resolvedDir(t, dir), "snyk.json")}, IgnoredWorkingDirConfigFiles(pinned, "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_UnreadableFileIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not restrict reads on windows")
	}
	isolateHome(t)
	dir := enterWorkingDirWithSnykJSON(t)
	require.NoError(t, os.Chmod(filepath.Join(dir, "snyk.json"), 0o000))

	// the file is reported without being read: its contents are never needed to decide that it is ignored
	assert.Equal(t, []string{filepath.Join(resolvedDir(t, dir), "snyk.json")}, IgnoredWorkingDirConfigFiles("", "snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_NameWithSeparatorIsSkipped(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "snyk.json"), []byte(workingDirSnykJSON), 0o644))

	// the rule is for a file directly in the working directory, so a name that reaches into a subdirectory is skipped
	assert.Nil(t, IgnoredWorkingDirConfigFiles("", "sub/snyk"))
}

func Test_IgnoredWorkingDirConfigFiles_UnknownHomeDirectoryReportsTheWorkingDirectoryFile(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	// without a home directory there is no configstore file, so the working directory file is ignored and reported
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	dir := enterWorkingDirWithSnykJSON(t)

	assert.Equal(t, []string{filepath.Join(resolvedDir(t, dir), "snyk.json")}, IgnoredWorkingDirConfigFiles("", "snyk"))
}
