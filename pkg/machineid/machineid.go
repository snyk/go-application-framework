// Package machineid resolves and persists a single machine identifier shared by every Snyk
// product on the same machine. The identifier is an opaque string with no defined format: it is
// stored and reported exactly as supplied by whichever source produced it. It is the one place
// that implements the resolution precedence (existing stored value, the shared file written by
// another Snyk product, an externally supplied value, an OS-derived identifier, an opt-in legacy
// value, or a freshly generated one) so every consumer of this framework converges on the same
// value.
package machineid

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
	"unicode"

	osid "github.com/denisbrodbeck/machineid"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// nopLogger is the fallback used wherever a logger was not supplied, so logging calls never need a
// nil check.
var nopLogger = zerolog.Nop()

// effectiveLogger returns logger, or a no-op logger if logger is nil.
func effectiveLogger(logger *zerolog.Logger) *zerolog.Logger {
	if logger == nil {
		return &nopLogger
	}
	return logger
}

// Source records how a machine identifier was resolved.
type Source string

const (
	// SourceProvided means the value came from the external injection channel (configuration.CLIENT_MACHINE_ID).
	SourceProvided Source = "provided"
	// SourceOS means the value came from the operating system's machine identifier.
	SourceOS Source = "os"
	// SourceLegacy means the value came from an opt-in legacy device-id file (see WithLegacyDeviceIDFile).
	SourceLegacy Source = "legacy"
	// SourceGenerated means the value was freshly generated because no other source applied.
	SourceGenerated Source = "generated"
)

// lockRetryDelay is how often Lock retries acquiring the storage or shared-file lock while blocked.
const lockRetryDelay = 100 * time.Millisecond

// lockTimeout bounds how long a storage or shared-file lock acquisition waits before giving up, so
// a holder that never releases (a crashed process, for example) cannot block resolution or Reset
// forever. It is a variable so tests can substitute a short bound instead of waiting out the real
// timeout.
var lockTimeout = 5 * time.Second

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

// knownSource reports whether s is one of the Source constants this package defines.
func knownSource(s Source) bool {
	switch s {
	case SourceProvided, SourceOS, SourceLegacy, SourceGenerated:
		return true
	default:
		return false
	}
}

// toKnownSource converts raw into a Source, falling back to SourceProvided when raw is not one of
// the Source constants this package defines. raw is untrusted wherever it was read back from the
// shared file or from configuration storage: both can be written by any Snyk product on the
// machine, or by a concurrent writer racing this process, so every read of identifier_source must
// go through this conversion rather than a bare Source(raw) cast.
func toKnownSource(raw string, logger *zerolog.Logger) Source {
	logger = effectiveLogger(logger)
	s := Source(raw)
	if knownSource(s) {
		return s
	}
	logger.Debug().Str("raw_source", raw).Msg("machine id: unrecognized identifier_source, falling back to provided")
	return SourceProvided
}

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID implementing
// the precedence order: an existing stored value (returned unchanged), the shared file written by
// another Snyk product, the external channel (configuration.CLIENT_MACHINE_ID), the OS machine
// identifier, an opt-in legacy file, or a freshly generated UUID. A value adopted from any source
// but the OS identifier is persisted into the shared file and into configuration storage; the OS
// identifier is persisted into configuration storage only, since every product derives it
// identically.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	var o resolveOptions
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	return func(config configuration.Configuration, existingValue any) (any, error) {
		return resolve(config, existingValue, o), nil
	}
}

func resolve(config configuration.Configuration, existingValue any, o resolveOptions) string {
	logger := o.logger

	if s, ok := existingValue.(string); ok && hasValue(s) {
		logger.Debug().Msg("machine id: using existing stored value")
		return s
	}

	if sf := readSharedFile(sharedFilePaths(), logger); sf != nil && hasValue(sf.MachineID) {
		// identifier_source is untrusted: the shared file can be written by any Snyk product on the
		// machine. The machine id itself is deliberately left unvalidated by design.
		source := toKnownSource(sf.IdentifierSource, logger)
		logger.Debug().Str("source", string(source)).Msg("machine id: adopting value from shared file")
		return adopt(config, sf.MachineID, source, false, logger)
	}

	if raw := config.GetString(configuration.CLIENT_MACHINE_ID); hasValue(raw) {
		logger.Debug().Msg("machine id: adopting value from external channel")
		return adopt(config, raw, SourceProvided, true, logger)
	}

	if id, err := osMachineID(); err == nil && hasValue(id) {
		logger.Debug().Msg("machine id: adopting OS-derived value")
		return adopt(config, id, SourceOS, false, logger)
	} else if err != nil {
		logger.Debug().Err(err).Msg("machine id: OS machine id lookup failed")
	}

	if o.legacyPath != "" && o.legacyParse != nil {
		if data, err := os.ReadFile(o.legacyPath); err == nil {
			if id, parseErr := o.legacyParse(data); parseErr == nil {
				id = strings.TrimRightFunc(id, unicode.IsSpace)
				if hasValue(id) {
					logger.Debug().Str("path", o.legacyPath).Msg("machine id: adopting value from legacy device-id file")
					return adopt(config, id, SourceLegacy, true, logger)
				}
			} else {
				logger.Debug().Err(parseErr).Str("path", o.legacyPath).Msg("machine id: legacy device-id file failed to parse")
			}
		} else {
			logger.Debug().Err(err).Str("path", o.legacyPath).Msg("machine id: legacy device-id file could not be read")
		}
	}

	logger.Debug().Msg("machine id: no source produced a value, generating one")
	return adopt(config, generate(), SourceGenerated, true, logger)
}

// adopt persists id/source and returns the value that ultimately won: writeShared additionally
// races the value into the shared file, and either step may instead surface a value a concurrent
// writer already stored, which is what the caller ends up returning.
func adopt(config configuration.Configuration, id string, source Source, writeShared bool, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	if writeShared {
		paths := sharedFilePaths()
		path := selectWritePath(paths, logger)
		writtenID, writtenSource, err := adoptOrWriteSharedFile(path, path == paths.perUser, id, source, logger)
		if err != nil && path == paths.machineWide && paths.perUser != "" {
			// selectWritePath's writability probe only checks the directory; a failure inside the
			// write itself (lock, temp file, rename) still needs a fallback to the per-user file.
			logger.Debug().Err(err).Str("path", path).Msg("machine id: machine-wide shared file write failed, falling back to per-user path")
			writtenID, writtenSource, err = adoptOrWriteSharedFile(paths.perUser, true, id, source, logger)
		}
		if err == nil {
			id, source = writtenID, writtenSource
		} else {
			logger.Debug().Err(err).Msg("machine id: shared file write failed on every candidate path")
		}
		// If every write attempt failed, keep resolving with our own candidate (id/source unchanged).
	}
	return mirrorIntoStorage(config, id, source, logger)
}

// adoptOrWriteSharedFile keeps whatever value the shared file already holds; otherwise it writes
// the candidate. createDir must be false for the machine-wide path.
func adoptOrWriteSharedFile(path string, createDir bool, candidateID string, candidateSource Source, logger *zerolog.Logger) (string, Source, error) {
	logger = effectiveLogger(logger)
	finalID, finalSource := candidateID, candidateSource
	err := writeSharedFileValue(path, createDir, func(sf *SharedFile) {
		if hasValue(sf.MachineID) {
			finalID, finalSource = sf.MachineID, toKnownSource(sf.IdentifierSource, logger)
			logger.Debug().Str("path", path).Str("source", string(finalSource)).Msg("machine id: concurrent writer already wrote a value to the shared file, adopting it")
			return
		}
		sf.MachineID = candidateID
		sf.IdentifierSource = string(candidateSource)
	}, logger)
	if err != nil {
		return candidateID, candidateSource, err
	}
	return finalID, finalSource, nil
}

// mirrorIntoStorage persists id/source into configuration storage (snyk.json), converging with a
// value a concurrent writer may have just stored, and updates the in-memory configuration so
// later lookups need no further I/O. Storage errors are swallowed; the resolved value is always
// returned.
//
// The re-check after Refresh reads into a scratch in-memory Configuration rather than config
// itself: config.GetString(configuration.MACHINE_ID) would re-invoke this very default value
// function, since Configuration re-runs a key's default function on every lookup.
func mirrorIntoStorage(config configuration.Configuration, id string, source Source, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	// MACHINE_ID must never become durably visible before MACHINE_ID_SOURCE does: resolve() treats
	// a stored MACHINE_ID alone as proof that resolution is complete and never re-checks the
	// source, so a partial write in the other order would strand every future run on an id with no
	// recorded source.
	persistInMemoryOnly := func(id string, source Source) string {
		config.Set(configuration.MACHINE_ID, id)
		config.Set(configuration.MACHINE_ID_SOURCE, string(source))
		return id
	}

	storage := config.GetStorage()
	if storage == nil {
		logger.Debug().Msg("machine id: no storage configured, keeping resolved value in memory only")
		return persistInMemoryOnly(id, source)
	}

	lockCtx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	if err := storage.Lock(lockCtx, lockRetryDelay); err != nil {
		logger.Debug().Err(err).Msg("machine id: storage lock timed out, keeping resolved value in memory only")
		return persistInMemoryOnly(id, source)
	}
	defer func() { _ = storage.Unlock() }() //nolint:errcheck // unlock errors are ignored; nothing actionable can be done with a failed unlock here

	refreshed := configuration.NewInMemory()
	//nolint:errcheck // a refresh miss just leaves refreshed empty, which the hasValue check below treats as "nothing stored yet"
	_ = storage.Refresh(refreshed, configuration.MACHINE_ID)
	//nolint:errcheck // a refresh miss just leaves refreshed empty, which the hasValue check below treats as "nothing stored yet"
	_ = storage.Refresh(refreshed, configuration.MACHINE_ID_SOURCE)

	if refreshedID := refreshed.GetString(configuration.MACHINE_ID); hasValue(refreshedID) {
		// identifier_source read back from storage is untrusted for the same reason the shared
		// file's is: a concurrent writer racing this process for the lock can be any Snyk product.
		id = refreshedID
		source = toKnownSource(refreshed.GetString(configuration.MACHINE_ID_SOURCE), logger)
		logger.Debug().Str("source", string(source)).Msg("machine id: storage already holds a value from a concurrent writer, adopting it")
	} else if err := storage.Set(configuration.MACHINE_ID_SOURCE, string(source)); err != nil {
		logger.Debug().Err(err).Msg("machine id: failed to persist machine id source to storage, keeping resolved value in memory only")
		return persistInMemoryOnly(id, source)
	} else {
		if err := storage.Set(configuration.MACHINE_ID, id); err != nil {
			// A failed write here still leaves the correct value in config.Set below for this process.
			logger.Debug().Err(err).Msg("machine id: failed to persist machine id to storage after its source was persisted")
		}
	}

	config.Set(configuration.MACHINE_ID, id)
	config.Set(configuration.MACHINE_ID_SOURCE, string(source))
	logger.Debug().Str("machine_id", id).Str("source", string(source)).Msg("machine id resolved")
	return id
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
//
// If a shared-file candidate cannot be cleared, Reset stops there and leaves storage untouched
// rather than clearing what it can: readSharedFile takes a shared file ahead of storage, so a
// candidate Reset failed to clear would still win the next resolution regardless of what happened
// to storage, making a storage clear in that case pure loss with no corresponding benefit.
func Reset(config configuration.Configuration, logger *zerolog.Logger) error {
	logger = effectiveLogger(logger)
	var resultErr error

	// The shared file is cleared before storage so that a resolve() racing with Reset can only ever
	// observe storage already cleared while the shared file still holds the old value (harmless: it
	// re-adopts the value Reset is about to discard anyway), never the reverse, which would let a
	// stale value survive Reset by being re-persisted into storage after Reset's own clear.
	paths := sharedFilePaths()
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		if err := removeSharedFileValue(p, logger); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}

	// A shared-file candidate Reset could not clear still holds the old machine id, and
	// readSharedFile takes it ahead of storage on the very next resolution, so clearing storage here
	// would only make Reset look like it succeeded while the effective machine id never changes.
	// Leaving storage untouched keeps it in a state Reset can still retry against, rather than
	// discarding a value that a resolve() is about to reconstruct from the shared file anyway.
	if resultErr != nil {
		return resultErr
	}

	if storage := config.GetStorage(); storage != nil {
		lockCtx, cancel := context.WithTimeout(context.Background(), lockTimeout)
		defer cancel()
		if err := storage.Lock(lockCtx, lockRetryDelay); err != nil {
			resultErr = errors.Join(resultErr, err)
		} else {
			// MACHINE_ID is deleted before MACHINE_ID_SOURCE, mirroring mirrorIntoStorage's write
			// order: MACHINE_ID's absence is what a future resolve() treats as "not yet resolved".
			if err := storage.Set(configuration.MACHINE_ID, configuration.Deleted); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
			if err := storage.Set(configuration.MACHINE_ID_SOURCE, configuration.Deleted); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
			_ = storage.Unlock() //nolint:errcheck // unlock errors are ignored; nothing actionable can be done with a failed unlock here
		}
	}

	config.Set(configuration.MACHINE_ID, nil)
	config.Set(configuration.MACHINE_ID_SOURCE, nil)

	return resultErr
}
