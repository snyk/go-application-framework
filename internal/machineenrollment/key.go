package machineenrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const pemType = "PRIVATE KEY"

// rsaKeyBits is the modulus size of generated keys; the enrollment service requires at least 2048.
const rsaKeyBits = 2048

// GenerateKey generates a new machine client key: an RSA key, for RS256 signatures, which is the
// algorithm the enrollment service and the OAuth token server accept.
func GenerateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed generating machine client key: %w", err)
	}
	return key, nil
}

// EncodeKeyPEM encodes key as a PKCS8 PEM.
func EncodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed encoding machine client key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// ParseKeyPEM parses a PKCS8 PEM key written by EncodeKeyPEM: an RSA key, or a P-256 ECDSA key.
func ParseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemType {
		return nil, errors.New("machine client key is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing machine client key: %w", err)
	}
	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		if key.Curve == elliptic.P256() {
			return key, nil
		}
	}
	return nil, errors.New("machine client key is not an RSA or P-256 key")
}
