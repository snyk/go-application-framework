package machineenrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// GenerateKey generates a new machine client key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating machine client key: %w", err)
	}
	return key, nil
}

// WriteKeyFile atomically replaces the key file at path with key, readable only by its owner.
func WriteKeyFile(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed encoding machine client key: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(path), keyDirMode); err != nil {
		return fmt.Errorf("failed creating machine client key directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed creating machine client key file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

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
		return fmt.Errorf("failed writing machine client key file: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed replacing machine client key file: %w", err)
	}
	return nil
}

// ReadKeyFile reads a key written by WriteKeyFile.
func ReadKeyFile(path string) (*ecdsa.PrivateKey, error) {
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
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("machine client key is not a P-256 key")
	}
	return key, nil
}
