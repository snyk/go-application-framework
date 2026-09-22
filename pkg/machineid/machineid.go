// Package machineid resolves and persists a single machine identifier shared by every Snyk
// product on the same machine. The identifier is an opaque string: it is stored and reported
// exactly as supplied by whichever source produced it, subject only to a basic sanity check
// (non-empty, bounded length, a safe character set) that rejects placeholder and malformed values
// before they are adopted.
//
// Resolution tries, in order: a value already resolved earlier in this process; an explicitly
// supplied value (configuration.CLIENT_MACHINE_ID); the shared file written by any Snyk product on
// the machine; a legacy single-value device-id file left behind by an older product installation;
// and finally a freshly generated UUIDv4. By default this never reads a hardware serial number or
// any other OS-derived identifier: doing so needs elevated privileges on some platforms, and an
// unprivileged caller that could not read it would silently mint a different identity than a
// privileged one on the very same machine. WithHardwareIdentity opts a caller into two additional
// sources, a hardware serial number and the hostname, for the one caller responsible for creating
// this identity in the first place; see its doc comment for the precedence and the privilege
// sequencing this places on that caller.
//
// A freshly generated value that could not be written anywhere durable (the shared file and
// configuration storage were both unavailable or failed) is still returned, but is recorded with
// source "ephemeral" rather than "generated": it will not survive to the next run, so callers that
// count distinct machines must not treat it as a stable identity.
package machineid

import (
	"context"
	"errors"
	"strings"
	"time"

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

// idSource records how a machine identifier was resolved.
type idSource string

const (
	// sourceProvided means the value came from the external injection channel (configuration.CLIENT_MACHINE_ID).
	sourceProvided idSource = "provided"
	// sourcePersisted means the value was read back from somewhere it was already durably stored:
	// the shared file, a legacy device-id file being migrated, or configuration storage.
	sourcePersisted idSource = "persisted"
	// sourceGenerated means the value was freshly generated and successfully persisted somewhere
	// durable.
	sourceGenerated idSource = "generated"
	// sourceEphemeral means the value was freshly generated but could not be persisted anywhere
	// durable, so it will not survive to the next run.
	sourceEphemeral idSource = "ephemeral"
	// sourceSerial means the value came from the machine's hardware serial number, read only when
	// WithHardwareIdentity is set.
	sourceSerial idSource = "serial"
	// sourceHostname means the value came from the machine's hostname, read only when
	// WithHardwareIdentity is set.
	sourceHostname idSource = "hostname"
	// sourceUnknown means a value read back from configuration storage carried a recorded source
	// this package does not recognize, e.g. because it was written by a newer or tampered writer.
	sourceUnknown idSource = "unknown"
)

// lockRetryDelay is how often Lock retries acquiring the storage or shared-file lock while blocked.
const lockRetryDelay = 100 * time.Millisecond

// lockTimeout bounds how long a storage or shared-file lock acquisition waits before giving up, so
// a holder that never releases (a crashed process, for example) cannot block resolution or reset
// forever. It is a variable so tests can substitute a short bound instead of waiting out the real
// timeout.
var lockTimeout = 5 * time.Second

// generate produces a fresh, lowercase UUIDv4.
func generate() string {
	return strings.ToLower(uuid.New().String())
}

// knownSource reports whether s is one of the idSource constants this package assigns itself. It
// is used only when reading a source back from configuration storage, the one place this package
// reads a source string it wrote earlier under its own control; shared-file and legacy-file reads
// never trust the source recorded there and always report sourcePersisted instead (see resolve).
func knownSource(s idSource) bool {
	switch s {
	case sourceProvided, sourcePersisted, sourceGenerated, sourceEphemeral, sourceSerial, sourceHostname:
		return true
	default:
		return false
	}
}

// toKnownSource converts raw into an idSource, falling back to sourceUnknown when raw is not one
// of the constants this package assigns. raw is untrusted wherever it was read back from
// configuration storage: a concurrent writer racing this process for the lock, or an older/newer
// version of this package, could have written anything there.
func toKnownSource(raw string, logger *zerolog.Logger) idSource {
	logger = effectiveLogger(logger)
	s := idSource(raw)
	if knownSource(s) {
		return s
	}
	logger.Debug().Str("raw_source", raw).Msg("machine id: unrecognized identifier_source, falling back to unknown")
	return sourceUnknown
}

// writerIdentity names the current consumer for the shared file's writer field, falling back to a
// generic framework identifier when Resolve was called without WithRuntimeInfo.
func writerIdentity(o resolveOptions) string {
	if o.runtimeInfo == nil {
		return defaultWriterIdentity
	}
	name := o.runtimeInfo.GetName()
	if blank(name) {
		return defaultWriterIdentity
	}
	if version := o.runtimeInfo.GetVersion(); !blank(version) {
		return name + "/" + version
	}
	return name
}

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID implementing
// the precedence order documented on the package.
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
	writer := writerIdentity(o)

	if s, ok := existingValue.(string); ok && !blank(s) {
		if valid(s) {
			logger.Debug().Msg("machine id: using existing stored value")
			return s
		}
		logger.Debug().Str("reason", invalidReason(s)).Msg("machine id: existing stored value failed validation, resolving again")
	}

	if raw := config.GetString(configuration.CLIENT_MACHINE_ID); !blank(raw) {
		if valid(raw) {
			logger.Debug().Msg("machine id: adopting value from external channel")
			return adopt(config, raw, sourceProvided, true, writer, logger)
		}
		logger.Debug().Str("reason", invalidReason(raw)).Msg("machine id: external channel value failed validation, ignoring")
	}

	// Both reads happen up front, before any source below has a chance to win, so a hostname read
	// during this same resolution can still be recorded into the shared file (via the deferred call
	// below) even when a higher-precedence source ends up winning the machine id itself.
	serialCandidate := readSerialCandidate(o.hardwareIdentity, logger)
	hostnameCandidate := readHostnameCandidate(o.hardwareIdentity, logger)
	if o.hardwareIdentity {
		defer recordHostnameMetadata(hostnameCandidate, writer, logger)
	}

	if !blank(serialCandidate) {
		logger.Debug().Msg("machine id: adopting value from hardware serial number")
		return adopt(config, serialCandidate, sourceSerial, true, writer, logger)
	}

	if sf := readSharedFile(sharedFilePaths(), logger); sf != nil {
		logger.Debug().Msg("machine id: adopting value from shared file")
		return adopt(config, sf.MachineID, sourcePersisted, false, writer, logger)
	}

	if id, path, ok := readLegacyDeviceID(legacyDeviceIDPaths(), logger); ok {
		logger.Debug().Str("path", path).Msg("machine id: adopting value from legacy device-id file")
		return adopt(config, id, sourcePersisted, true, writer, logger)
	}

	if !blank(hostnameCandidate) {
		logger.Debug().Msg("machine id: adopting value from hostname")
		return adopt(config, hostnameCandidate, sourceHostname, false, writer, logger)
	}

	logger.Debug().Msg("machine id: no source produced a value, generating one")
	return adopt(config, generate(), sourceGenerated, true, writer, logger)
}

// adopt persists id/source (best-effort) and returns the value that ultimately wins the race
// against any concurrent writer. If source is sourceGenerated and persistence fails everywhere
// (shared file and configuration storage), it is downgraded to sourceEphemeral: analytics counts
// distinct machines by source, and a value that survives nowhere would otherwise be minted again
// on every future run while still being counted as if it were a stable identity.
func adopt(config configuration.Configuration, id string, source idSource, writeShared bool, writer string, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	persisted := false

	if writeShared {
		paths := sharedFilePaths()
		path := selectWritePath(paths, logger)
		// An explicitly supplied id is authoritative and must converge every product on the
		// machine onto it, overwriting whatever the shared file already holds; a generated or
		// migrated-legacy id must instead defer to a value already there, which is either another
		// product's already-established identity or a concurrent writer that won the same race.
		overwrite := source == sourceProvided
		writtenID, wonByOther, err := adoptOrWriteSharedFile(path, path == paths.perUser, id, source, writer, overwrite, logger)
		if err != nil && path == paths.machineWide && paths.perUser != "" {
			// selectWritePath's writability probe only checks the directory; a failure inside the
			// write itself (lock, temp file, rename) still needs a fallback to the per-user file.
			logger.Debug().Err(err).Str("path", path).Msg("machine id: machine-wide shared file write failed, falling back to per-user path")
			writtenID, wonByOther, err = adoptOrWriteSharedFile(paths.perUser, true, id, source, writer, overwrite, logger)
		}
		switch {
		case err == nil && wonByOther:
			id, source = writtenID, sourcePersisted
			persisted = true
		case err == nil:
			id = writtenID
			persisted = true
		default:
			logger.Debug().Err(err).Msg("machine id: shared file write failed on every candidate path")
		}
	}

	return mirrorIntoStorage(config, id, source, persisted, logger)
}

// adoptOrWriteSharedFile keeps whatever value the shared file already holds when a concurrent
// writer won the race to write it first, otherwise writes the candidate. wonByOther reports which
// happened, so the caller can tell a value it wrote itself apart from one it merely adopted.
// overwrite skips that deference entirely, unconditionally writing the candidate: it is set for an
// explicitly supplied id, which must converge every product on the machine onto it rather than
// defer to whatever happens to already be in the file.
func adoptOrWriteSharedFile(path string, createDir bool, candidateID string, candidateSource idSource, writer string, overwrite bool, logger *zerolog.Logger) (id string, wonByOther bool, err error) {
	logger = effectiveLogger(logger)
	id = candidateID
	err = writeSharedFileValue(path, createDir, writer, func(sf *sharedFile) {
		// A hardware serial number is stamped into serial_number regardless of which value wins the
		// machine_id race below: other Snyk products use it for correlation, and it is the same value
		// on this machine no matter which concurrent writer's candidate is adopted as the id.
		if candidateSource == sourceSerial {
			sf.SerialNumber = candidateID
		}
		if !overwrite && !blank(sf.MachineID) && valid(sf.MachineID) {
			id = sf.MachineID
			wonByOther = true
			logger.Debug().Str("path", path).Msg("machine id: concurrent writer already wrote a value to the shared file, adopting it")
			return
		}
		sf.MachineID = candidateID
		sf.IdentifierSource = string(candidateSource)
	}, logger)
	if err != nil {
		return candidateID, false, err
	}
	return id, wonByOther, nil
}

// mirrorIntoStorage persists id/source into configuration storage (snyk.json), converging with a
// value a concurrent writer may have just stored, and updates the in-memory configuration so later
// lookups need no further I/O. Storage errors are swallowed; the resolved value is always
// returned. persistedElsewhere reports whether writeShared already durably stored id, which
// combined with whatever this function itself manages decides the sourceGenerated/sourceEphemeral
// downgrade.
//
// The re-check after Refresh reads into a scratch in-memory Configuration rather than config
// itself: config.GetString(configuration.MACHINE_ID) would re-invoke this very default value
// function, since Configuration re-runs a key's default function on every lookup.
func mirrorIntoStorage(config configuration.Configuration, id string, source idSource, persistedElsewhere bool, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	persisted := persistedElsewhere

	finalize := func(id string, source idSource) string {
		if source == sourceGenerated && !persisted {
			source = sourceEphemeral
		}
		config.Set(configuration.MACHINE_ID, id)
		config.Set(configuration.MACHINE_ID_SOURCE, string(source))
		logger.Debug().Str("machine_id", id).Str("source", string(source)).Msg("machine id resolved")
		return id
	}

	storage := config.GetStorage()
	if storage == nil {
		logger.Debug().Msg("machine id: no storage configured, keeping resolved value in memory only")
		return finalize(id, source)
	}

	lockCtx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	if err := storage.Lock(lockCtx, lockRetryDelay); err != nil {
		logger.Debug().Err(err).Msg("machine id: storage lock timed out, keeping resolved value in memory only")
		return finalize(id, source)
	}
	defer func() { _ = storage.Unlock() }() //nolint:errcheck // unlock errors are ignored; nothing actionable can be done with a failed unlock here

	refreshed := configuration.NewInMemory()
	//nolint:errcheck // a refresh miss just leaves refreshed empty, which the check below treats as "nothing stored yet"
	_ = storage.Refresh(refreshed, configuration.MACHINE_ID)
	//nolint:errcheck // a refresh miss just leaves refreshed empty, which the check below treats as "nothing stored yet"
	_ = storage.Refresh(refreshed, configuration.MACHINE_ID_SOURCE)

	if refreshedID := refreshed.GetString(configuration.MACHINE_ID); !blank(refreshedID) && valid(refreshedID) {
		// identifier_source read back here is trusted only as far as knownSource goes: this key is
		// only ever written by this package, but a concurrent writer could be an older or newer
		// version of it.
		id = refreshedID
		source = toKnownSource(refreshed.GetString(configuration.MACHINE_ID_SOURCE), logger)
		persisted = true
		logger.Debug().Str("source", string(source)).Msg("machine id: storage already holds a value from a concurrent writer, adopting it")
		return finalize(id, source)
	}

	// MACHINE_ID must never become durably visible before MACHINE_ID_SOURCE does: resolve() treats
	// a stored MACHINE_ID alone as proof that resolution is complete and never re-checks the
	// source, so a partial write in the other order would strand every future run on an id with no
	// recorded source.
	if err := storage.Set(configuration.MACHINE_ID_SOURCE, string(source)); err != nil {
		logger.Debug().Err(err).Msg("machine id: failed to persist machine id source to storage, keeping resolved value in memory only")
		return finalize(id, source)
	}
	if err := storage.Set(configuration.MACHINE_ID, id); err != nil {
		logger.Debug().Err(err).Msg("machine id: failed to persist machine id to storage after its source was persisted")
		return finalize(id, source)
	}

	persisted = true
	return finalize(id, source)
}

// reset clears the resolved machine identifier from configuration storage and from the shared
// file, so the next Resolve call starts over from the top of the precedence order documented on
// the package instead of reusing the value from a previous run, under the same locks Resolve uses.
//
// If a shared-file candidate cannot be cleared, reset stops there and leaves storage untouched
// rather than clearing what it can: readSharedFile takes a shared file ahead of storage, so a
// candidate reset failed to clear would still win the next resolution regardless of what happened
// to storage, making a storage clear in that case pure loss with no corresponding benefit.
func reset(config configuration.Configuration, opts ...ResolveOption) error {
	var o resolveOptions
	for _, opt := range opts {
		opt(&o)
	}
	logger := effectiveLogger(o.logger)
	var resultErr error

	// The shared file is cleared before storage so that a resolve() racing with reset can only ever
	// observe storage already cleared while the shared file still holds the old value (harmless: it
	// re-adopts the value reset is about to discard anyway), never the reverse, which would let a
	// stale value survive reset by being re-persisted into storage after reset's own clear.
	paths := sharedFilePaths()
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		if err := removeSharedFileValue(p, defaultWriterIdentity, logger); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}

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
