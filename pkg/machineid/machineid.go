// Package machineid resolves and persists a single machine identifier shared by every Snyk
// product on the same machine. The identifier is an opaque string with no defined format: it is
// stored and reported exactly as supplied by whichever source produced it. It is the one place
// that implements the resolution precedence (existing stored value, an externally supplied value,
// an OS-derived identifier, an opt-in legacy value, or a freshly generated one) so every consumer
// of this framework converges on the same value.
package machineid

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	osid "github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Source records how a machine identifier was resolved.
type Source string

const (
	// SourceProvided means the value came from the external injection channel (configuration.CLIENT_MACHINE_ID).
	SourceProvided Source = "provided"
	// SourceOS means the value came from the operating system's machine identifier.
	SourceOS Source = "os"
	// SourceLegacy means the value came from an opt-in legacy device-id file (see WithLegacyDeviceIdFile).
	SourceLegacy Source = "legacy"
	// SourceGenerated means the value was freshly generated because no other source applied.
	SourceGenerated Source = "generated"
)

// lockRetryDelay is how often Lock retries acquiring the storage or shared-file lock while blocked.
const lockRetryDelay = 100 * time.Millisecond

// osMachineID is a variable so tests can substitute a deterministic identifier instead of the
// current machine's real one.
var osMachineID = osid.ID

// hasValue reports whether raw is more than whitespace. This is presence, not validation: the
// precedence chain uses it to decide whether a candidate source supplied anything at all, and the
// value itself is otherwise adopted unexamined, with no format, charset, or length constraint.
func hasValue(raw string) bool {
	return strings.TrimSpace(raw) != ""
}

// generate produces a fresh, lowercase UUIDv4.
func generate() string {
	return strings.ToLower(uuid.New().String())
}

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID implementing
// the precedence order: an existing stored value (returned unchanged), the external channel
// (configuration.CLIENT_MACHINE_ID), the OS machine identifier, an opt-in legacy file, or a
// freshly generated UUID. A value adopted from any source but the OS identifier is persisted into
// the shared file and into configuration storage; the OS identifier is persisted into
// configuration storage only, since every product derives it identically.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	var o resolveOptions
	for _, opt := range opts {
		opt(&o)
	}
	return func(config configuration.Configuration, existingValue any) (any, error) {
		return resolve(config, existingValue, o)
	}
}

func resolve(config configuration.Configuration, existingValue any, o resolveOptions) (string, error) {
	if s, ok := existingValue.(string); ok && hasValue(s) {
		return s, nil
	}

	if sf := readSharedFile(sharedFilePaths()); sf != nil && hasValue(sf.MachineID) {
		return adopt(config, sf.MachineID, Source(sf.IdentifierSource), false)
	}

	if raw := config.GetString(configuration.CLIENT_MACHINE_ID); hasValue(raw) {
		return adopt(config, raw, SourceProvided, true)
	}

	if id, err := osMachineID(); err == nil && hasValue(id) {
		return adopt(config, id, SourceOS, false)
	}

	if o.legacyPath != "" && o.legacyParse != nil {
		if data, err := os.ReadFile(o.legacyPath); err == nil {
			if id, err := o.legacyParse(data); err == nil && hasValue(id) {
				return adopt(config, id, SourceLegacy, true)
			}
		}
	}

	return adopt(config, generate(), SourceGenerated, true)
}

// adopt persists id/source and returns the value that ultimately won: writeShared additionally
// races the value into the shared file, and either step may instead surface a value a concurrent
// writer already stored, which is what the caller ends up returning.
func adopt(config configuration.Configuration, id string, source Source, writeShared bool) (string, error) {
	if writeShared {
		paths := sharedFilePaths()
		path := selectWritePath(paths)
		id, source = adoptOrWriteSharedFile(path, path == paths.perUser, id, source)
	}
	id, _ = mirrorIntoStorage(config, id, source)
	return id, nil
}

// adoptOrWriteSharedFile keeps whatever value the shared file already holds; otherwise it writes
// the candidate. createDir must be false for the machine-wide path.
func adoptOrWriteSharedFile(path string, createDir bool, candidateID string, candidateSource Source) (string, Source) {
	finalID, finalSource := candidateID, candidateSource
	err := writeSharedFileValue(path, createDir, func(sf *SharedFile) {
		if hasValue(sf.MachineID) {
			finalID, finalSource = sf.MachineID, Source(sf.IdentifierSource)
			return
		}
		sf.MachineID = candidateID
		sf.IdentifierSource = string(candidateSource)
	})
	if err != nil {
		// Shared-file write failed (e.g. unwritable path); keep resolving with our own candidate.
		return candidateID, candidateSource
	}
	return finalID, finalSource
}

// mirrorIntoStorage persists id/source into configuration storage (snyk.json), converging with a
// value a concurrent writer may have just stored, and updates the in-memory configuration so
// later lookups need no further I/O. Storage errors are swallowed; the resolved value is always
// returned.
//
// The re-check after Refresh reads into a scratch in-memory Configuration rather than config
// itself: config.GetString(configuration.MACHINE_ID) would re-invoke this very default value
// function, since Configuration re-runs a key's default function on every lookup.
func mirrorIntoStorage(config configuration.Configuration, id string, source Source) (string, Source) {
	storage := config.GetStorage()
	if storage == nil {
		config.Set(configuration.MACHINE_ID, id)
		config.Set(configuration.MACHINE_ID_SOURCE, string(source))
		return id, source
	}

	if err := storage.Lock(context.Background(), lockRetryDelay); err != nil {
		config.Set(configuration.MACHINE_ID, id)
		config.Set(configuration.MACHINE_ID_SOURCE, string(source))
		return id, source
	}
	defer func() { _ = storage.Unlock() }() //nolint:errcheck // unlock errors are ignored, matching syncTokenRefresh in pkg/auth

	refreshed := configuration.NewInMemory()
	//nolint:errcheck // a refresh miss just leaves refreshed empty, which the hasValue check below treats as "nothing stored yet"
	_ = storage.Refresh(refreshed, configuration.MACHINE_ID)
	//nolint:errcheck // a refresh miss just leaves refreshed empty, which the hasValue check below treats as "nothing stored yet"
	_ = storage.Refresh(refreshed, configuration.MACHINE_ID_SOURCE)

	if refreshedID := refreshed.GetString(configuration.MACHINE_ID); hasValue(refreshedID) {
		id = refreshedID
		source = Source(refreshed.GetString(configuration.MACHINE_ID_SOURCE))
	} else {
		//nolint:errcheck // a failed write here still leaves the correct value in config.Set below for this process
		_ = storage.Set(configuration.MACHINE_ID, id)
		//nolint:errcheck // a failed write here still leaves the correct value in config.Set below for this process
		_ = storage.Set(configuration.MACHINE_ID_SOURCE, string(source))
	}

	config.Set(configuration.MACHINE_ID, id)
	config.Set(configuration.MACHINE_ID_SOURCE, string(source))
	return id, source
}

// EnsurePersisted forces one resolution and returns its result, so the machine identifier is
// generated and durably stored even for a run that never triggers a lookup on its own (for
// example one that emits no analytics event).
func EnsurePersisted(config configuration.Configuration) (string, error) {
	value, err := config.GetWithError(configuration.MACHINE_ID)
	if err != nil {
		return "", err
	}
	//nolint:errcheck // zero-value fallback on type mismatch is intentional
	id, _ := value.(string)
	return id, nil
}

// Reset removes the stored machine identifier and its source from configuration storage and from
// the shared file, under the same locks Resolve uses. The next resolution runs the precedence
// order from the top.
func Reset(config configuration.Configuration) error {
	var resultErr error

	if storage := config.GetStorage(); storage != nil {
		if err := storage.Lock(context.Background(), lockRetryDelay); err != nil {
			resultErr = err
		} else {
			if err := storage.Set(configuration.MACHINE_ID, struct{}{}); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
			if err := storage.Set(configuration.MACHINE_ID_SOURCE, struct{}{}); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
			_ = storage.Unlock() //nolint:errcheck // unlock errors are ignored, matching syncTokenRefresh in pkg/auth
		}
	}

	config.Set(configuration.MACHINE_ID, nil)
	config.Set(configuration.MACHINE_ID_SOURCE, nil)

	paths := sharedFilePaths()
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		if err := removeSharedFileValue(p); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}

	return resultErr
}
