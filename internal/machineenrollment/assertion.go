package machineenrollment

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// ClientAssertionType is the client_assertion_type of a private_key_jwt client assertion.
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// clientAssertionLifetime bounds how long a client assertion can be used.
	clientAssertionLifetime = 5 * time.Minute
)

// ClientAssertion returns a private_key_jwt client assertion (RFC 7523) for clientID, signed by
// key, for a token request to tokenURL. Each assertion has a unique jti, so the authorization
// server accepts it once.
func ClientAssertion(key crypto.Signer, clientID, tokenURL string, now time.Time) (string, error) {
	kid, err := thumbprint(key.Public())
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err = rand.Read(jti); err != nil {
		return "", fmt.Errorf("failed generating jti: %w", err)
	}

	// No iat or nbf: the authorization server checks them without clock skew leeway, so a client
	// clock running slightly fast would get the assertion rejected.
	return signJWT(key, "JWT", map[string]any{"kid": kid}, map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenURL,
		"jti": hex.EncodeToString(jti),
		"exp": now.Add(clientAssertionLifetime).Unix(),
	})
}
