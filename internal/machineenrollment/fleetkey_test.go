package machineenrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
	return path
}

func TestReadFleetKeyFile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	for name, path := range map[string]string{
		"PKCS8": writePEM(t, "PRIVATE KEY", pkcs8),
		"SEC1":  writePEM(t, "EC PRIVATE KEY", sec1),
	} {
		got, err := ReadFleetKeyFile(path)
		require.NoError(t, err, name)
		assert.True(t, key.Equal(got), name)
	}
}

func TestReadFleetKeyFileRejectsOtherKeys(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	notPEM := filepath.Join(t.TempDir(), "x")
	require.NoError(t, os.WriteFile(notPEM, []byte("hello"), 0o600))

	for name, path := range map[string]string{
		"P-384":      writePEM(t, "PRIVATE KEY", p384DER),
		"RSA":        writePEM(t, "PRIVATE KEY", rsaDER),
		"garbage":    writePEM(t, "PRIVATE KEY", []byte("garbage")),
		"wrong type": writePEM(t, "CERTIFICATE", p384DER),
		"not PEM":    notPEM,
		"missing":    filepath.Join(t.TempDir(), "missing.pem"),
	} {
		_, err := ReadFleetKeyFile(path)
		assert.Error(t, err, name)
	}
}

func TestFleetKeyAuthorizationClaims(t *testing.T) {
	fleetKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientKey, err := GenerateKey()
	require.NoError(t, err)
	now := time.Now()

	token, err := fleetKeyAuthorization(fleetKey, clientKey, "https://api.example.com/hidden/machines/enrollments",
		[]Identifier{{Type: "serial_number", Value: "C02XK1JHJG5J"}}, now)
	require.NoError(t, err)

	header, claims, _, _ := splitJWT(t, token)
	kid, err := thumbprint(&fleetKey.PublicKey)
	require.NoError(t, err)
	jkt, err := thumbprint(&clientKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"alg": "ES256", "typ": "fleet-key-authorization+jwt", "kid": kid}, header)
	assert.Equal(t, "https://api.example.com/hidden/machines/enrollments", claims["aud"])
	assert.InDelta(t, now.Unix(), claims["iat"], 1)
	assert.Equal(t, []any{map[string]any{"type": "serial_number", "value": "C02XK1JHJG5J"}}, claims["identifiers"])
	assert.Equal(t, map[string]any{"jkt": jkt}, claims["cnf"])
}
