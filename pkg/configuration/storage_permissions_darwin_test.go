package configuration_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_Configuration_ReadableFile_ChmodFailure(t *testing.T) {
	const immutable = 0x2 // Darwin UF_IMMUTABLE.
	t.Setenv("HOME", t.TempDir())
	file := filepath.Join(os.Getenv("HOME"), ".config", "configstore", "snyk.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0755))
	require.NoError(t, os.WriteFile(file, []byte(`{"api":"initial-token"}`), 0644))
	t.Cleanup(func() { assert.NoError(t, syscall.Chflags(file, 0)) })
	// Immutable files remain readable while rejecting chmod and writes.
	require.NoError(t, syscall.Chflags(file, immutable))
	require.ErrorIs(t, os.Chmod(file, 0600), os.ErrPermission)

	config := configuration.NewWithOpts(configuration.WithFiles("snyk"))
	assert.Equal(t, "initial-token", config.GetString("api"))

	require.NoError(t, syscall.Chflags(file, 0))
	const updated = `{"api":"updated-token"}`
	require.NoError(t, os.WriteFile(file, []byte(updated), 0644))
	require.NoError(t, syscall.Chflags(file, immutable))
	require.ErrorIs(t, config.ReloadConfig(), os.ErrPermission)
	assert.Equal(t, "updated-token", config.GetString("api"))

	require.ErrorIs(t, config.GetStorage().Set("api", "new-token"), os.ErrPermission)
	contents, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, updated, string(contents))
}
