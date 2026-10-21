package machineenrollment

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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
	assert.True(t, second.Equal(got), "the stored RSA key is read back")

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
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)

	files := map[string][]byte{
		"p384.pem":    pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}),
		"ed25519.pem": pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: edDER}),
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

func TestGenerateKeyIsRSA(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, key.N.BitLen(), 2048)
}

func TestReadKeyFileAcceptsP256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.NoError(t, WriteKeyFile(path, key))

	got, err := ReadKeyFile(path)
	require.NoError(t, err)
	assert.True(t, key.Equal(got))
}

func TestEncodeAndParseKeyPEM(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	encoded, err := EncodeKeyPEM(key)
	require.NoError(t, err)
	got, err := ParseKeyPEM(encoded)

	require.NoError(t, err)
	assert.True(t, key.Equal(got), "the RSA key is read back")
}

func TestParseKeyPEMRejectsOtherKeys(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)

	inputs := map[string][]byte{
		"p384":    pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}),
		"ed25519": pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: edDER}),
		"garbage": []byte("not a key"),
		"empty":   nil,
	}
	for name, data := range inputs {
		_, parseErr := ParseKeyPEM(data)
		assert.Error(t, parseErr, name)
	}
}

func TestParseKeyPEMAcceptsP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encoded, err := EncodeKeyPEM(key)
	require.NoError(t, err)

	got, err := ParseKeyPEM(encoded)

	require.NoError(t, err)
	assert.True(t, key.Equal(got))
}
