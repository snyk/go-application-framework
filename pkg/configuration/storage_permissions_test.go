//go:build unix

package configuration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_JsonStorage_Permissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		exists bool
		mode   os.FileMode
	}{
		{name: "absent"},
		{name: "private", exists: true, mode: 0600},
		{name: "group and other readable", exists: true, mode: 0644},
		{name: "group and other writable", exists: true, mode: 0666},
		{name: "executable", exists: true, mode: 0755},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), "config.json")
			if tt.exists {
				require.NoError(t, os.WriteFile(file, []byte(`{"existing":"value"}`), 0600))
				require.NoError(t, os.Chmod(file, tt.mode))
			}

			storage := configuration.NewJsonStorage(file)
			require.NoError(t, storage.Set(key, expectedValue))

			info, err := os.Stat(file)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
			stored := readStoredConfigFile(t, file)
			assert.Equal(t, expectedValue, stored[key])
			if tt.exists {
				assert.Equal(t, "value", stored["existing"])
			}
		})
	}
}

func Test_Configuration_Load_DoesNotChangePermissions(t *testing.T) {
	tests := []struct {
		name   string
		exists bool
		mode   os.FileMode
	}{
		{name: "absent"},
		{name: "owner read only", exists: true, mode: 0400},
		{name: "group readable read only", exists: true, mode: 0440},
		{name: "private", exists: true, mode: 0600},
		{name: "group and other readable", exists: true, mode: 0644},
		{name: "group and other writable", exists: true, mode: 0666},
		{name: "executable", exists: true, mode: 0755},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			file := filepath.Join(os.Getenv("HOME"), ".config", "configstore", "snyk.json")
			const contents = `{"api":"dummy-token","existing":"value"}`
			if tt.exists {
				require.NoError(t, os.MkdirAll(filepath.Dir(file), 0755))
				require.NoError(t, os.WriteFile(file, []byte(contents), 0600))
				require.NoError(t, os.Chmod(file, tt.mode))
			}

			config := configuration.NewWithOpts(configuration.WithFiles("snyk"))
			info, err := os.Stat(file)
			if !tt.exists {
				require.ErrorIs(t, err, os.ErrNotExist)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.mode, info.Mode().Perm())
			assert.Equal(t, "dummy-token", config.GetString("api"))
			assert.Equal(t, "value", config.GetString("existing"))
			actual, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Equal(t, contents, string(actual))

			require.NoError(t, config.ReloadConfig())
			info, err = os.Stat(file)
			require.NoError(t, err)
			assert.Equal(t, tt.mode, info.Mode().Perm())
		})
	}
}

func Test_JsonStorage_Refresh_Permissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		mode         os.FileMode
		expectedMode os.FileMode
	}{
		{name: "private", mode: 0600, expectedMode: 0600},
		{name: "group and other readable", mode: 0644, expectedMode: 0600},
		{name: "owner read only", mode: 0400, expectedMode: 0400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(file, []byte(`{"someKey":"someValue"}`), 0600))
			require.NoError(t, os.Chmod(file, tt.mode))

			storage := configuration.NewJsonStorage(file)
			config := configuration.NewWithOpts()
			require.NoError(t, storage.Refresh(config, key))
			assert.Equal(t, expectedValue, config.GetString(key))

			info, err := os.Stat(file)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedMode, info.Mode().Perm())
		})
	}
}

func Test_Configuration_PermissionFailure_PreservesFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	t.Setenv("HOME", t.TempDir())
	dir := filepath.Join(os.Getenv("HOME"), ".config", "configstore")
	file := filepath.Join(dir, "snyk.json")
	const contents = `{"api":"old-token"}`
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(file, []byte(contents), 0600))
	config := configuration.NewWithOpts(configuration.WithFiles("snyk"))

	require.NoError(t, os.Chmod(dir, 0))
	t.Cleanup(func() { assert.NoError(t, os.Chmod(dir, 0755)) })
	require.ErrorIs(t, config.ReloadConfig(), os.ErrPermission)
	require.ErrorIs(t, config.GetStorage().Set("api", "new-token"), os.ErrPermission)
	config.PersistInStorage("api")
	config.Set("api", "new-token")
	require.NoError(t, os.Chmod(dir, 0755))
	actual, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, contents, string(actual))
}
