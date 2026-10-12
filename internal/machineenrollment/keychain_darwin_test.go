//go:build darwin && cgo

package machineenrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemKeychainSigns signs with a real keychain identity issued by the CA in the PEM file
// named by MACHINE_ENROLLMENT_TEST_CA_PEM. It is skipped unless that is set, because it needs a
// managed device and macOS asks the user to allow access to the key.
func TestSystemKeychainSigns(t *testing.T) {
	caFile := os.Getenv("MACHINE_ENROLLMENT_TEST_CA_PEM")
	if caFile == "" {
		t.Skip("MACHINE_ENROLLMENT_TEST_CA_PEM is not set")
	}
	data, err := os.ReadFile(caFile)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	ca, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	keychain := SystemKeychain()
	identity, err := keychain.Identity([][]byte{ca.RawSubject})
	require.NoError(t, err)
	defer identity.Close()
	t.Logf("identity: %s (serial %x, expires %s)", identity.Certificate().Subject, identity.Certificate().SerialNumber, identity.Certificate().NotAfter)
	t.Logf("device: %+v", keychain.DeviceInfo())

	digest := sha256.Sum256([]byte("machine enrollment keychain test"))
	sig, err := identity.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err)

	switch pub := identity.Public().(type) {
	case *rsa.PublicKey:
		assert.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))
		pss, pssErr := identity.Sign(nil, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		require.NoError(t, pssErr)
		assert.NoError(t, rsa.VerifyPSS(pub, crypto.SHA256, digest[:], pss, nil))
	case *ecdsa.PublicKey:
		assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
	default:
		t.Fatalf("unexpected key type %T", pub)
	}

	// And as a JWT, which is how enrollment uses it.
	token, err := signJWT(identity, nil, map[string]any{"test": true})
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSystemKeychainWithNoAcceptedIssuer(t *testing.T) {
	_, err := SystemKeychain().Identity([][]byte{[]byte("not an issuer anyone uses")})

	assert.ErrorIs(t, err, ErrNoIdentity)
}

func TestSystemKeychainDeviceInfo(t *testing.T) {
	info := SystemKeychain().DeviceInfo()

	assert.NotEmpty(t, info.UDID)
}
