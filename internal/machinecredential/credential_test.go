package machinecredential_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func fileBackedConfig(t *testing.T) func() configuration.Configuration {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return func() configuration.Configuration {
		return configuration.NewWithOpts(configuration.WithFiles("snyk"))
	}
}

func newCredential(t *testing.T) machinecredential.Credential {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	return machinecredential.Credential{ClientID: "client-1", Key: key}
}

func TestLoad_NothingStoredIsNotEnrolled(t *testing.T) {
	_, err := machinecredential.Load(configuration.NewWithOpts())

	assert.ErrorIs(t, err, machinecredential.ErrNotEnrolled)
}

func TestLoad_RejectsUnusableValues(t *testing.T) {
	validKeyPEM, err := machineenrollment.EncodeKeyPEM(newCredential(t).Key)
	require.NoError(t, err)
	stored := func(clientID, keyPEM string) string {
		b, marshalErr := json.Marshal(map[string]string{"client_id": clientID, "private_key_pem": keyPEM})
		require.NoError(t, marshalErr)
		return string(b)
	}

	for name, value := range map[string]string{
		"malformed json": "{not json",
		"bad pem":        stored("client-1", "not a pem"),
		"missing key":    stored("client-1", ""),
		"missing client": stored("", string(validKeyPEM)),
	} {
		t.Run(name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, value)

			_, loadErr := machinecredential.Load(config)

			require.Error(t, loadErr)
			assert.NotErrorIs(t, loadErr, machinecredential.ErrNotEnrolled)
		})
	}
}

func TestSaveThenLoad_AcrossConfigurationInstances(t *testing.T) {
	open := fileBackedConfig(t)
	credential := newCredential(t)

	require.NoError(t, machinecredential.Save(t.Context(), open(), credential))
	loaded, err := machinecredential.Load(open())

	require.NoError(t, err)
	assert.Equal(t, credential.ClientID, loaded.ClientID)
	original, ok := credential.Key.(interface{ Equal(crypto.PrivateKey) bool })
	require.True(t, ok, "the key type can compare itself")
	assert.True(t, original.Equal(loaded.Key), "the multi-line PEM survives the file")
}

func TestClear_RemovesTheStoredCredential(t *testing.T) {
	open := fileBackedConfig(t)
	require.NoError(t, machinecredential.Save(t.Context(), open(), newCredential(t)))

	machinecredential.Clear(open())

	_, err := machinecredential.Load(open())
	assert.ErrorIs(t, err, machinecredential.ErrNotEnrolled)
}

func TestSave_WritesOneValueUnderTheStorageLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	config := configuration.NewWithOpts()
	config.SetStorage(storage)

	var written any
	gomock.InOrder(
		storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(nil),
		storage.EXPECT().Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, gomock.Any()).DoAndReturn(func(_ string, value any) error {
			written = value
			return nil
		}).Times(1),
		storage.EXPECT().Unlock().Return(nil),
	)

	require.NoError(t, machinecredential.Save(t.Context(), config, newCredential(t)))

	assert.Contains(t, written, `"client_id":"client-1"`)
	assert.Contains(t, written, `"private_key_pem"`)
}

func TestSave_FailsWithoutWritingWhenTheLockCannotBeTaken(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	config := configuration.NewWithOpts()
	config.SetStorage(storage)
	storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(context.DeadlineExceeded)

	err := machinecredential.Save(t.Context(), config, newCredential(t))

	require.ErrorIs(t, err, context.DeadlineExceeded)
	_, loadErr := machinecredential.Load(config)
	assert.ErrorIs(t, loadErr, machinecredential.ErrNotEnrolled, "nothing is kept in memory either")
}

func TestSigner_AssertionVerifiesAgainstTheKey(t *testing.T) {
	credential := newCredential(t)
	signer := machinecredential.NewSigner(credential.Key)

	assertionType, assertion, err := signer.ClientAssertion(t.Context(), "client-1", "https://api.example.test/oauth2/token")

	require.NoError(t, err)
	assert.Equal(t, machineenrollment.ClientAssertionType, assertionType)
	require.NoError(t, enrollmenttest.VerifyJWT(assertion, credential.Key.Public()))
	_, claims := enrollmenttest.DecodeJWT(t, assertion)
	assert.Equal(t, "client-1", claims["iss"])
	assert.Equal(t, "client-1", claims["sub"])
	assert.Equal(t, "https://api.example.test/oauth2/token", claims["aud"])
}

func configFilePath(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	return filepath.Join(home, ".config", "configstore", "snyk.json")
}

func TestSave_ReportsACorruptConfigFile(t *testing.T) {
	open := fileBackedConfig(t)
	path := configFilePath(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	config := open()

	err := machinecredential.Save(t.Context(), config, newCredential(t))

	require.Error(t, err)
	assert.Empty(t, config.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE), "the in-memory view does not claim an unsaved value")
}

func TestSave_ReportsAnUnwritableConfigFile(t *testing.T) {
	open := fileBackedConfig(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(configFilePath(t)), 0o755))
	require.NoError(t, os.WriteFile(configFilePath(t), []byte("{}"), 0o444))
	if f, openErr := os.OpenFile(configFilePath(t), os.O_WRONLY, 0); openErr == nil {
		_ = f.Close()
		t.Skip("file permissions are not enforced here (running as a privileged user)")
	}

	err := machinecredential.Save(t.Context(), open(), newCredential(t))

	assert.Error(t, err)
}

func TestSave_NeedsStorage(t *testing.T) {
	config := configuration.NewWithOpts()
	config.SetStorage(nil)

	err := machinecredential.Save(t.Context(), config, newCredential(t))

	require.Error(t, err)
	assert.Empty(t, config.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE))
}

func TestSave_ReturnsTheStorageErrorAndKeepsNothingInMemory(t *testing.T) {
	ctrl := gomock.NewController(t)
	storage := mocks.NewMockStorage(ctrl)
	config := configuration.NewWithOpts()
	config.SetStorage(storage)
	writeErr := errors.New("disk full")
	storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(nil)
	storage.EXPECT().Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, gomock.Any()).Return(writeErr).Times(1)
	storage.EXPECT().Unlock().Return(nil)

	err := machinecredential.Save(t.Context(), config, newCredential(t))

	require.ErrorIs(t, err, writeErr)
	assert.Empty(t, config.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE))
}

var _ auth.ClientAssertionProvider = (*machinecredential.Signer)(nil)

func TestSecretTerms_SkipShortPEMLines(t *testing.T) {
	config := configuration.NewWithOpts()
	stored, err := json.Marshal(map[string]string{
		"client_id":       "client-1",
		"private_key_pem": "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAA\nQQ==\n-----END PRIVATE KEY-----\n",
	})
	require.NoError(t, err)
	config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(stored))

	terms := machinecredential.SecretTerms(config)

	assert.Contains(t, terms, "AAAAAAAAAAAAAAAAAAAAAAAA")
	assert.Contains(t, terms, "client-1")
	assert.NotContains(t, terms, "QQ==", "a short line would redact unrelated text")
}
