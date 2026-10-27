package machineenrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// maxFleetKeyFileBytes bounds what is read from a fleet key file, which holds one small key.
const maxFleetKeyFileBytes = 64 << 10

// IdentifierTypeSerialNumber is the type of a hardware serial number, the only identifier the
// enrollment service knows.
const IdentifierTypeSerialNumber = "serial_number"

// Identifier names a machine, as an admin registered it.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ReadFleetKeyFile reads a fleet key: the private half of the P-256 keypair an admin registered, as a
// PEM file with a PKCS8 ("PRIVATE KEY") or SEC1 ("EC PRIVATE KEY") key. The file must be a regular
// file.
func ReadFleetKeyFile(path string) (*ecdsa.PrivateKey, error) {
	f, err := openWithoutBlocking(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading fleet key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed reading fleet key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("fleet key file is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFleetKeyFileBytes))
	if err != nil {
		return nil, fmt.Errorf("failed reading fleet key file: %w", err)
	}
	block, err := fleetKeyBlock(data)
	if err != nil {
		return nil, err
	}

	var key any
	switch block.Type {
	case pemType:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed parsing fleet key: %w", err)
	}
	if ec, ok := key.(*ecdsa.PrivateKey); ok && ec.Curve == elliptic.P256() {
		return ec, nil
	}
	return nil, errors.New("fleet key is not a P-256 key")
}

var errEncryptedFleetKey = errors.New("fleet key file is encrypted: the fleet key must be an unencrypted PEM private key")

// fleetKeyBlock returns the first private key block of a PEM file, skipping the EC PARAMETERS block
// openssl writes before the key.
func fleetKeyBlock(data []byte) (*pem.Block, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("fleet key file is not a PEM private key")
		}
		data = rest
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			return nil, errEncryptedFleetKey
		case pemType, "EC PRIVATE KEY":
			if len(block.Headers) != 0 {
				return nil, errEncryptedFleetKey
			}
			return block, nil
		}
	}
}

// fleetKeyAuthorization returns the authorization of a fleet key enrollment: the identifiers of the
// machine, signed by the fleet key and bound to clientKey, the key the machine enrolls with.
func fleetKeyAuthorization(fleetKey *ecdsa.PrivateKey, clientKey crypto.Signer, audience string, identifiers []Identifier, now time.Time) (string, error) {
	kid, err := thumbprint(&fleetKey.PublicKey)
	if err != nil {
		return "", err
	}
	jkt, err := thumbprint(clientKey.Public())
	if err != nil {
		return "", err
	}
	return signJWT(fleetKey, fleetAuthorizationTyp, map[string]any{"kid": kid}, map[string]any{
		"aud":         audience,
		"iat":         now.Unix(),
		"identifiers": identifiers,
		"cnf":         map[string]string{"jkt": jkt},
	})
}

func validateIdentifiers(identifiers []Identifier) error {
	if len(identifiers) == 0 || len(identifiers) > maxIdentifiers {
		return ErrNoIdentifiers
	}
	for _, id := range identifiers {
		if id.Type == "" || id.Value == "" || len([]rune(id.Value)) > maxIdentifierValueChars || strings.ContainsRune(id.Value, 0) {
			return ErrNoIdentifiers
		}
	}
	return nil
}
