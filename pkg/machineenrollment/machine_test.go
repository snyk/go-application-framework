package machineenrollment_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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
	token := srv.IssueDeviceToken(srv.RegisterMachine())

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, keyFile)

	e, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithDeviceToken(token))
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

	if runtime.GOOS != "windows" { // Windows ignores POSIX permission bits
		info, err := os.Stat(keyFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestEnrollMachineUsesDefaultKeyFileWhenNoneConfigured(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueDeviceToken(srv.RegisterMachine())

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)

	e, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithDeviceToken(token))
	require.NoError(t, err)

	defaultKeyFile, err := machineenrollment.DefaultKeyFile()
	require.NoError(t, err)
	assert.Equal(t, defaultKeyFile, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE))

	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(defaultKeyFile)) })
	assert.NotEmpty(t, e.ClientID)
}

func TestEnrollMachineWithFleetKeyFile(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	fleetKey := newFleetKey(t)
	srv.AllowFleetKey(&fleetKey.PublicKey, srv.RegisterMachine("SERIAL-1"))
	der, err := x509.MarshalPKCS8PrivateKey(fleetKey)
	require.NoError(t, err)
	fleetKeyFile := filepath.Join(t.TempDir(), "fleet.pem")
	require.NoError(t, os.WriteFile(fleetKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, filepath.Join(t.TempDir(), "key.pem"))
	source := func(context.Context) ([]machineenrollment.Identifier, error) { return serials("SERIAL-1"), nil }

	e, err := machineenrollment.EnrollMachine(context.Background(), config,
		machineenrollment.WithFleetKeyFile(fleetKeyFile), machineenrollment.WithIdentifierSource(source))
	require.NoError(t, err)

	assert.Equal(t, "machine-1", e.MachineID)
	assert.Equal(t, e.ClientID, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
}

func TestEnrollMachineReportsIdentifierSourceFailures(t *testing.T) {
	fleetKey := newFleetKey(t)
	der, err := x509.MarshalECPrivateKey(fleetKey)
	require.NoError(t, err)
	fleetKeyFile := filepath.Join(t.TempDir(), "fleet.pem")
	require.NoError(t, os.WriteFile(fleetKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600))
	config := configuration.NewInMemory()
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, filepath.Join(t.TempDir(), "key.pem"))
	source := func(context.Context) ([]machineenrollment.Identifier, error) {
		return nil, machineenrollment.ErrUnsupportedPlatform
	}

	_, err = machineenrollment.EnrollMachine(context.Background(), config,
		machineenrollment.WithFleetKeyFile(fleetKeyFile), machineenrollment.WithIdentifierSource(source))

	assert.ErrorIs(t, err, machineenrollment.ErrUnsupportedPlatform)
}

func TestEnrollMachineNeedsExactlyOneJoinMaterial(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, filepath.Join(t.TempDir(), "key.pem"))

	_, err := machineenrollment.EnrollMachine(context.Background(), config)
	assert.Error(t, err)

	_, err = machineenrollment.EnrollMachine(context.Background(), config,
		machineenrollment.WithDeviceToken("sdt_a"), machineenrollment.WithFleetKeyFile("fleet.pem"))
	assert.Error(t, err)
}
