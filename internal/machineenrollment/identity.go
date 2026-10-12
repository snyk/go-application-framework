package machineenrollment

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"slices"
	"time"
)

var (
	// ErrUnsupported is returned on platforms without device identity support.
	ErrUnsupported = errors.New("device identities are not supported on this platform")

	// ErrNoIdentity is returned when no identity in the keychain was issued by an accepted issuer.
	ErrNoIdentity = errors.New("no device identity certificate from an accepted issuer was found")
)

// DeviceIdentity is an identity certificate and the private key that goes with it. The key may
// live in a keychain and never leave it; signing with it can prompt the user.
type DeviceIdentity interface {
	crypto.Signer
	Certificate() *x509.Certificate
	Close()
}

// DeviceInfo identifies the hardware. Either field may be empty if it can't be read.
type DeviceInfo struct {
	UDID   string
	Serial string
}

// Keychain finds device identities.
type Keychain interface {
	// Identity returns the identity whose certificate was issued by one of acceptedIssuers (DER
	// encoded subject names), or ErrNoIdentity.
	Identity(acceptedIssuers [][]byte) (DeviceIdentity, error)
	// DeviceInfo returns the hardware identifiers of this device.
	DeviceInfo() DeviceInfo
}

// selectCertificate returns the index of the certificate to use: one issued by an accepted issuer,
// currently valid and usable for client authentication. If several are, it prefers the one that
// expires last. It returns -1 if none is.
func selectCertificate(certs []*x509.Certificate, acceptedIssuers [][]byte, now time.Time) int {
	best := -1
	for i, c := range certs {
		if c == nil || now.Before(c.NotBefore) || now.After(c.NotAfter) || !usableForClientAuth(c) {
			continue
		}
		if !slices.ContainsFunc(acceptedIssuers, func(issuer []byte) bool { return bytes.Equal(issuer, c.RawIssuer) }) {
			continue
		}
		if best == -1 || c.NotAfter.After(certs[best].NotAfter) {
			best = i
		}
	}
	return best
}

func usableForClientAuth(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 {
		return true
	}
	return slices.ContainsFunc(c.ExtKeyUsage, func(u x509.ExtKeyUsage) bool {
		return u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny
	})
}
