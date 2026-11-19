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
