package machineenrollment_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/machineenrollment/enrollmenttest"
)

func TestEnrollMachine(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueJoinToken()

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, keyFile)

	e, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithJoinKey(token, "machine-known"))
	require.NoError(t, err)

	assert.Equal(t, "client-1", e.ClientID)
	require.NotNil(t, e.Key)
	assert.True(t, e.Key.PublicKey.Equal(srv.ClientKey(e.ClientID)))

	assert.Equal(t, e.ClientID, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
	assert.Equal(t, keyFile, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE))
	assert.Equal(t, e.MachineID, config.GetString(machineenrollment.CONFIG_KEY_MACHINE_ID))

	stored, err := machineenrollment.ReadKeyFile(keyFile)
	require.NoError(t, err)
	assert.True(t, e.Key.Equal(stored))

	if runtime.GOOS != "windows" { // Windows does not honour POSIX permission bits
		info, err := os.Stat(keyFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestEnrollMachineUsesDefaultKeyFileWhenNoneConfigured(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueJoinToken()

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)

	e, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithJoinKey(token, "machine-known"))
	require.NoError(t, err)

	defaultKeyFile, err := machineenrollment.DefaultKeyFile()
	require.NoError(t, err)
	assert.Equal(t, defaultKeyFile, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE))

	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(defaultKeyFile)) })
	assert.NotEmpty(t, e.ClientID)
}
