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
	"os"
	"path/filepath"
)

const (
	keyFileMode = 0o600
	keyDirMode  = 0o700
	pemType     = "PRIVATE KEY"
)

// DefaultKeyFile returns where the machine client's private key is stored by default.
func DefaultKeyFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed finding home directory: %w", err)
	}
	return filepath.Join(home, ".snyk", "machine-client", "key.pem"), nil
}

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

// WriteKeyFile atomically replaces the key file at path with key, readable only by its owner.
func WriteKeyFile(path string, key crypto.Signer) error {
	tmp, err := stageKeyFile(path, key)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	return replaceKeyFile(tmp, path)
}

// stageKeyFile writes key to a new 0600 file in the same directory as path and returns that path.
// The caller renames it onto path or removes it; this function does not.
func stageKeyFile(path string, key crypto.Signer) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, keyDirMode); err != nil {
		return "", fmt.Errorf("failed creating machine client key directory: %w", err)
	}
	return writeKeyTemp(dir, filepath.Base(path), key)
}

func writeKeyTemp(dir, base string, key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed encoding machine client key: %w", err)
	}
	tmp, err := os.CreateTemp(dir, base+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed creating machine client key file: %w", err)
	}
	tmpName := tmp.Name()

	if err = tmp.Chmod(keyFileMode); err == nil {
		err = pem.Encode(tmp, &pem.Block{Type: pemType, Bytes: der})
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("failed writing machine client key file: %w", err)
	}
	return tmpName, nil
}

func replaceKeyFile(tmp, path string) error {
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed replacing machine client key file: %w", err)
	}
	return nil
}

// ReadKeyFile reads a PKCS8 PEM key written by WriteKeyFile: an RSA key, or a P-256 ECDSA key.
func ReadKeyFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading machine client key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemType {
		return nil, errors.New("machine client key file is not a PEM private key")
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
