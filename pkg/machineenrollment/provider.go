package machineenrollment

import (
	"context"
	"fmt"
	"time"

	"github.com/snyk/go-application-framework/pkg/auth"
)

// assertionProvider implements auth.ClientAssertionProvider by signing client assertions with the
// machine client key read from keyFile.
type assertionProvider struct {
	keyFile string
}

var _ auth.ClientAssertionProvider = (*assertionProvider)(nil)

// NewAssertionProvider returns an auth.ClientAssertionProvider that authenticates with the machine
// client key stored at keyFile, as written by EnrollMachine.
func NewAssertionProvider(keyFile string) auth.ClientAssertionProvider {
	return &assertionProvider{keyFile: keyFile}
}

// ClientAssertion implements auth.ClientAssertionProvider.
func (p *assertionProvider) ClientAssertion(_ context.Context, clientID, tokenURL string) (string, string, error) {
	key, err := ReadKeyFile(p.keyFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to read machine client key: %w", err)
	}
	assertion, err := ClientAssertion(key, clientID, tokenURL, time.Now())
	if err != nil {
		return "", "", err
	}
	return ClientAssertionType, assertion, nil
}
