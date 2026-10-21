package machinecredential

import (
	"context"
	"crypto"
	"time"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
)

// Signer signs client assertions with a key held in memory.
type Signer struct {
	key crypto.Signer
}

// NewSigner returns a Signer for key.
func NewSigner(key crypto.Signer) *Signer {
	return &Signer{key: key}
}

// ClientAssertion returns the client assertion type and a client assertion for clientID, addressed
// to tokenURL.
func (s *Signer) ClientAssertion(_ context.Context, clientID, tokenURL string) (string, string, error) {
	assertion, err := machineenrollment.ClientAssertion(s.key, clientID, tokenURL, time.Now())
	if err != nil {
		return "", "", err
	}
	return machineenrollment.ClientAssertionType, assertion, nil
}
