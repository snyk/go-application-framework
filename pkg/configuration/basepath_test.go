package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_BasePath_IsTheConfigstoreInTheHomeDirectory(t *testing.T) {
	isolateHome(t)
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	p, err := basePath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".config", "configstore"), p)
	assert.Equal(t, p, determineBasePath())
}

func Test_BasePath_WithoutHomeDirectory_IsAnErrorNotTheWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	p, err := basePath()
	assert.Error(t, err)
	assert.Empty(t, p)
	assert.Empty(t, determineBasePath(), `a relative "." must never be returned`)
}

// Test_BasePath_WithRelativeHomeDirectory_IsAnErrorNotTheWorkingDirectory checks that a relative home directory fails
// closed. os.UserHomeDir returns the variable as it is, so HOME=relhome would name relhome/.config/configstore under the
// working directory. Neither that directory nor the working directory may be read or written.
func Test_BasePath_WithRelativeHomeDirectory_IsAnErrorNotTheWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	t.Setenv("HOME", "relhome")
	t.Setenv("USERPROFILE", "relhome")
	cwd := t.TempDir()
	t.Chdir(cwd)
	storeDir := filepath.Join(cwd, "relhome", ".config", "configstore")
	require.NoError(t, os.MkdirAll(storeDir, 0o755))
	storeFile := filepath.Join(storeDir, "snyk.json")
	require.NoError(t, os.WriteFile(storeFile, []byte(`{"org":"relhome-org"}`), 0o600))
	workingFile := filepath.Join(cwd, "snyk.json")
	require.NoError(t, os.WriteFile(workingFile, []byte(`{"org":"attacker-org"}`), 0o644))

	p, err := basePath()
	assert.ErrorContains(t, err, "not an absolute path")
	assert.Empty(t, p)
	dir, err := DefaultStorageDir()
	assert.ErrorContains(t, err, "not an absolute path")
	assert.Empty(t, dir)

	c := NewWithOpts(WithFiles("snyk"))
	assert.Empty(t, c.GetString("org"), "neither the relative store nor the working directory file is read")
	assert.Nil(t, c.GetStorage(), "the configuration is in memory without storage")
	c.PersistInStorage("org")
	c.Set("org", "written-by-cli")
	_, err = CreateConfigurationFile("snyk.json")
	assert.ErrorContains(t, err, "not an absolute path")

	content, err := os.ReadFile(storeFile)
	require.NoError(t, err)
	assert.JSONEq(t, `{"org":"relhome-org"}`, string(content), "the relative store is not written")
	content, err = os.ReadFile(workingFile)
	require.NoError(t, err)
	assert.JSONEq(t, `{"org":"attacker-org"}`, string(content), "the working directory file is not written")
	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "only the two files the test wrote are in the working directory")
}

func Test_DefaultStorageDir_WithoutHomeDirectory_IsAnErrorWrappingTheCause(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	dir, err := DefaultStorageDir()
	require.Error(t, err)
	assert.Empty(t, dir, "no directory is returned with the error, so a relative path cannot be joined onto it")
	assert.ErrorContains(t, err, "configuration storage unavailable")
	assert.ErrorContains(t, err, "home directory could not be determined")
	assert.ErrorContains(t, err, "not defined", "the os.UserHomeDir error is wrapped; its text differs per platform")
}

func Test_WithFiles_WithoutHomeDirectory_IsInMemoryWithoutStorage(t *testing.T) {
	if runtime.GOOS == "plan9" {
		t.Skip("the home directory is read from $home on plan9, which this test cannot unset on every platform")
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	c := NewWithOpts(WithFiles("snyk"))
	assert.Equal(t, inMemory, asViper(t, c).getConfigType())
	assert.Nil(t, c.GetStorage())
	assert.Equal(t, []string{"snyk"}, asViper(t, c).GetFiles(), "the requested files are kept for Clone and Derive")
}
