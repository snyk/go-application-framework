package machineenrollment_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

func TestEnrollMachineDoesNotCallServerWhenKeyCannotBeWritten(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueDeviceToken(srv.RegisterMachine())
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(parent, []byte("x"), 0o600))

	var calls int
	base := srv.Client().Transport
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return base.RoundTrip(r)
	})}

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, filepath.Join(parent, "key.pem"))

	_, err := machineenrollment.EnrollMachine(context.Background(), config,
		machineenrollment.WithDeviceToken(token), machineenrollment.WithHttpClient(client))

	require.Error(t, err)
	assert.Zero(t, calls, "a key that cannot be stored must not be sent to the enrollment service")
	assert.Zero(t, srv.ClientCount())
	assert.Empty(t, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))

	enrolled, err := machineenrollment.EnrollWithDeviceToken(context.Background(), srv.Client(), srv.URL, token, time.Now())
	require.NoError(t, err, "the device token is still unused")
	assert.NotEmpty(t, enrolled.ClientID)
}

func TestEnrollMachineDoesNotStageKeyWhenJoinMaterialIsInvalid(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "nested", "key.pem")
	config := configuration.NewInMemory()
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, keyFile)

	_, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithDeviceToken("nope"))

	assert.ErrorIs(t, err, machineenrollment.ErrMalformedDeviceToken)
	_, statErr := os.Stat(filepath.Dir(keyFile))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestEnrollMachineRemovesStagedKeyWhenEnrollmentFails(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	existing := []byte("existing-key")
	require.NoError(t, os.WriteFile(keyFile, existing, 0o600))

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, keyFile)

	_, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithDeviceToken("sdt_not-issued"))

	require.Error(t, err)
	var enrollErr *machineenrollment.EnrollmentError
	require.ErrorAs(t, err, &enrollErr)
	assert.Zero(t, srv.ClientCount())
	assert.Empty(t, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
	got, readErr := os.ReadFile(keyFile)
	require.NoError(t, readErr)
	assert.Equal(t, existing, got)
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Len(t, entries, 1)
}

func TestEnrollMachineRemovesStagedKeyWhenFleetKeyEnrollIsRejected(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	machineID := srv.RegisterMachine("SERIAL-1")
	_, err := machineenrollment.EnrollWithDeviceToken(context.Background(), srv.Client(), srv.URL, srv.IssueDeviceToken(machineID), time.Now())
	require.NoError(t, err)

	fleetKey := newFleetKey(t)
	srv.AllowFleetKey(&fleetKey.PublicKey, machineID)
	der, err := x509.MarshalPKCS8PrivateKey(fleetKey)
	require.NoError(t, err)
	fleetKeyFile := filepath.Join(t.TempDir(), "fleet.pem")
	require.NoError(t, os.WriteFile(fleetKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))

	dir := t.TempDir()
	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, filepath.Join(dir, "key.pem"))
	source := func(context.Context) ([]machineenrollment.Identifier, error) { return serials("SERIAL-1"), nil }

	_, err = machineenrollment.EnrollMachine(context.Background(), config,
		machineenrollment.WithFleetKeyFile(fleetKeyFile), machineenrollment.WithIdentifierSource(source))

	assert.ErrorIs(t, err, machineenrollment.ErrMachineEnrolled)
	assert.Equal(t, 1, srv.ClientCount(), "the rejected enroll must not bind another client")
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
	assert.Empty(t, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
}

func TestEnrollMachineReportsWhereTheKeyIsWhenItCannotBeMoved(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueDeviceToken(srv.RegisterMachine())
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.Mkdir(keyFile, 0o700))

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, keyFile)

	_, err := machineenrollment.EnrollMachine(context.Background(), config, machineenrollment.WithDeviceToken(token))

	var saved *machineenrollment.KeyNotSavedError
	require.ErrorAs(t, err, &saved)
	assert.ErrorIs(t, err, machineenrollment.ErrKeyNotSaved)
	assert.Equal(t, 1, srv.ClientCount())
	assert.Equal(t, "client-1", saved.ClientID)
	assert.Contains(t, err.Error(), saved.ClientID)
	assert.Contains(t, err.Error(), "do not enroll again")
	assert.Equal(t, keyFile, saved.DestPath)
	info, statErr := os.Stat(keyFile)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir(), "the blocked destination is left untouched")

	stored, readErr := machineenrollment.ReadKeyFile(saved.KeyPath)
	require.NoError(t, readErr)
	pub, ok := stored.Public().(*rsa.PublicKey)
	require.True(t, ok)
	assert.True(t, pub.Equal(srv.ClientKey(saved.ClientID)))
	assert.Empty(t, config.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
	if runtime.GOOS != "windows" {
		staged, statErr := os.Stat(saved.KeyPath)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), staged.Mode().Perm())
	}
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
