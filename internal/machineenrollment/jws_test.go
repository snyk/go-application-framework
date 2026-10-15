package machineenrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignJWTWithES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token, err := signJWT(key, map[string]any{"kid": "k"}, map[string]any{"sub": "me"})
	require.NoError(t, err)

	header, claims, sig, digest := splitJWT(t, token)
	assert.Equal(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "k"}, header)
	assert.Equal(t, map[string]any{"sub": "me"}, claims)
	require.Len(t, sig, 64, "ES256 signatures are R || S")
	assert.True(t, ecdsa.Verify(&key.PublicKey, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])))
}

func TestSignJWTWithRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token, err := signJWT(key, nil, map[string]any{"sub": "me"})
	require.NoError(t, err)

	header, _, sig, digest := splitJWT(t, token)
	assert.Equal(t, "RS256", header["alg"])
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, sig))
}

func TestSignJWTRejectsUnsupportedKeys(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = signJWT(ed, nil, map[string]any{})
	assert.Error(t, err)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = signJWT(p384, nil, map[string]any{})
	assert.Error(t, err)
}

func TestThumbprintRSA(t *testing.T) {
	// The example key from RFC 7638 section 3.1.
	n, err := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	require.NoError(t, err)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}

	got, err := thumbprint(pub)
	require.NoError(t, err)

	assert.Equal(t, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", got)
}

func TestThumbprintEC(t *testing.T) {
	// Check against a value computed independently from the canonical JWK.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := publicJWK(&key.PublicKey)
	require.NoError(t, err)
	canonical, err := json.Marshal(map[string]string{"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]})
	require.NoError(t, err)
	want := sha256.Sum256(canonical)

	got, err := thumbprint(&key.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, base64.RawURLEncoding.EncodeToString(want[:]), got)
}

func splitJWT(t *testing.T, token string) (header, claims map[string]any, sig, digest []byte) {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	for i, out := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, out))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return header, claims, sig, sum[:]
}
