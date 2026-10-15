package machineenrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndReadKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-client", "key.pem")
	first, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, WriteKeyFile(path, first))

	second, err := GenerateKey()
	require.NoError(t, err)
	require.NoError(t, WriteKeyFile(path, second), "an existing key is replaced")

	got, err := ReadKeyFile(path)
	require.NoError(t, err)
	assert.True(t, got.Equal(second))

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		dir, statErr := os.Stat(filepath.Dir(path))
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o700), dir.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temp files are left behind")
}

func TestReadKeyFileRejectsOtherKeys(t *testing.T) {
	dir := t.TempDir()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)

	files := map[string][]byte{
		"ec.pem":      pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}),
		"garbage.pem": []byte("not a key"),
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		_, readErr := ReadKeyFile(path)
		assert.Error(t, readErr, name)
	}

	_, err = ReadKeyFile(filepath.Join(dir, "missing.pem"))
	assert.Error(t, err)
}
