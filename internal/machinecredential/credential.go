// Package machinecredential stores the credential of an enrolled machine as one configuration value
// and signs client assertions with it. It must not import pkg/auth or pkg/workflow: pkg/auth depends
// on it.
package machinecredential

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// CONFIG_KEY_MACHINE_IDENTITY_STORAGE holds the JSON encoded credential of the enrolled machine.
const CONFIG_KEY_MACHINE_IDENTITY_STORAGE = "INTERNAL_MACHINE_IDENTITY_STORAGE"

// CONFIG_KEY_DEVICE_TOKEN is the configuration key of the single-use device token that machine.enroll
// takes as its --device-token flag. It lives here so that log scrubbing can redact it without
// importing the workflow.
const CONFIG_KEY_DEVICE_TOKEN = "device-token"

const minPEMLineLength = 16

const storageLockRetryDelay = 100 * time.Millisecond

// ErrNotEnrolled is returned by Load when no credential is stored.
var ErrNotEnrolled = errors.New("this machine is not enrolled")

// Credential is what an enrolled machine authenticates with.
type Credential struct {
	ClientID string
	Key      crypto.Signer
}

type storedCredential struct {
	ClientID      string `json:"client_id"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

// Save persists credential as a single configuration value. It writes through the storage
// directly, because Configuration.Set drops storage errors, and only then updates the in-memory view.
func Save(ctx context.Context, config configuration.Configuration, credential Credential) error {
	keyPEM, err := machineenrollment.EncodeKeyPEM(credential.Key)
	if err != nil {
		return err
	}
	value, err := json.Marshal(storedCredential{ClientID: credential.ClientID, PrivateKeyPEM: string(keyPEM)})
	if err != nil {
		return fmt.Errorf("failed encoding machine credential: %w", err)
	}

	storage := config.GetStorage()
	if storage == nil {
		return errors.New("the configuration has no storage to persist the machine credential in")
	}
	// The lock only excludes other lock holders (token refresh, Save); other persisted writes take
	// an in-process mutex only.
	if err = storage.Lock(ctx, storageLockRetryDelay); err != nil {
		return fmt.Errorf("failed locking the configuration storage: %w", err)
	}
	defer func() { _ = storage.Unlock() }() //nolint:errcheck // nothing to do about a failed unlock

	if err = storage.Set(CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(value)); err != nil {
		return fmt.Errorf("failed storing machine credential: %w", err)
	}
	// Set before PersistInStorage, so a first save does not write the value a second time.
	config.Set(CONFIG_KEY_MACHINE_IDENTITY_STORAGE, string(value))
	config.PersistInStorage(CONFIG_KEY_MACHINE_IDENTITY_STORAGE)
	return nil
}

// Load reads the stored credential, or returns ErrNotEnrolled when there is none.
func Load(config configuration.Configuration) (Credential, error) {
	value := config.GetString(CONFIG_KEY_MACHINE_IDENTITY_STORAGE)
	if value == "" {
		return Credential{}, ErrNotEnrolled
	}

	var stored storedCredential
	if err := json.Unmarshal([]byte(value), &stored); err != nil {
		return Credential{}, fmt.Errorf("failed decoding machine credential: %w", err)
	}
	if stored.ClientID == "" {
		return Credential{}, errors.New("machine credential has no client id")
	}
	key, err := machineenrollment.ParseKeyPEM([]byte(stored.PrivateKeyPEM))
	if err != nil {
		return Credential{}, err
	}
	return Credential{ClientID: stored.ClientID, Key: key}, nil
}

// SecretTerms returns the values of the stored credential that must not appear in logs: the client
// id, the PEM of the key and each of its lines. It reads the stored value without validating it, so
// it also covers a credential Load rejects.
func SecretTerms(config configuration.Configuration) []string {
	var stored storedCredential
	if err := json.Unmarshal([]byte(config.GetString(CONFIG_KEY_MACHINE_IDENTITY_STORAGE)), &stored); err != nil {
		return nil
	}
	terms := []string{stored.ClientID, strings.TrimSpace(stored.PrivateKeyPEM)}
	for _, line := range strings.Split(stored.PrivateKeyPEM, "\n") {
		// The whole PEM term covers the key; short lines would only redact unrelated text.
		if line = strings.TrimSpace(line); len(line) >= minPEMLineLength && !strings.HasPrefix(line, "-----") {
			terms = append(terms, line)
		}
	}
	return terms
}

// Clear removes the stored credential.
func Clear(config configuration.Configuration) {
	config.Unset(CONFIG_KEY_MACHINE_IDENTITY_STORAGE)
}
