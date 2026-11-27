package machineenrollment

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestGenerateKeyIsRSA(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, key.N.BitLen(), 2048)
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
