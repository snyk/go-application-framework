// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine. The identifier is an opaque string: it is stored and reported exactly as
// supplied by whichever source produced it, subject only to a basic sanity check (non-empty,
// bounded length, a safe character set) that rejects placeholder and malformed values.
//
// Resolution tries, in order: an explicitly supplied value (configuration.CLIENT_MACHINE_ID); the
// shared machine-id file written by any Snyk product on the machine; the device-id file written by
// Snyk Studio; and finally a freshly generated UUIDv4. The shared file is the only place the
// identifier is stored. An explicitly supplied value is used but never written there, so it cannot
// replace the identity other Snyk products on the machine share. A generated value that cannot be
// written there is not a stable identity, so configuration.MACHINE_ID is empty in that case.
package machineid

import (
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// sharedFilePaths is a variable so tests can point it at temporary directories; the machine-wide
// path on Linux and macOS is a fixed OS path that a test process cannot write to without root.
var sharedFilePaths = defaultSharedFilePaths

// idSource records in the shared file how its machine identifier was obtained.
type idSource string

const (
	sourcePersisted idSource = "persisted"
	sourceGenerated idSource = "generated"
)

func generate() string {
	return strings.ToLower(uuid.New().String())
}

// defaultWriterIdentity is recorded as the writer field when the consumer did not identify itself.
const defaultWriterIdentity = "go-application-framework"

// writerIdentity names the current consumer for the shared file's writer field.
func writerIdentity(o resolveOptions) string {
	if o.runtimeInfo == nil {
		return defaultWriterIdentity
	}
	ri := o.runtimeInfo()
	if ri == nil {
		return defaultWriterIdentity
	}
	name := ri.GetName()
	if blank(name) {
		return defaultWriterIdentity
	}
	if version := ri.GetVersion(); !blank(version) {
		return name + "/" + version
	}
	return name
}

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID implementing
// the precedence order documented on the package. A value resolved from disk is kept in memory
// for the life of the returned function, so repeated lookups do not touch the file system again.
// An empty result is not kept, so a later lookup retries once the cause (a held lock, a missing
// permission) has cleared. An explicitly supplied value is checked on every lookup and always wins.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	var o resolveOptions
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	r := &resolver{opts: o}
	return func(config configuration.Configuration, _ any) (any, error) {
		return r.resolve(config), nil
	}
}

type resolver struct {
	opts resolveOptions

	mu       sync.Mutex
	fromDisk string
}

func (r *resolver) resolve(config configuration.Configuration) string {
	logger := r.opts.logger

	if raw := config.GetString(configuration.CLIENT_MACHINE_ID); !blank(raw) {
		if valid(raw) {
			logger.Debug().Msg("machine id: adopting value from external channel")
			return raw
		}
		logger.Debug().Str("reason", invalidReason(raw)).Msg("machine id: external channel value failed validation, ignoring")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fromDisk == "" {
		r.fromDisk = r.resolveFromDisk()
	}
	return r.fromDisk
}

func (r *resolver) resolveFromDisk() string {
	logger := r.opts.logger
	writer := writerIdentity(r.opts)
	paths := sharedFilePaths()

	if sf := readSharedFile(paths, logger); sf != nil {
		logger.Debug().Msg("machine id: adopting value from shared file")
		return sf.MachineID
	}

	if id, path, ok := readStudioDeviceID(studioDeviceIDPaths(), logger); ok {
		logger.Debug().Str("path", path).Msg("machine id: adopting value from Snyk Studio device-id file")
		stored, err := writeSharedFileID(paths, id, string(sourcePersisted), writer, logger)
		if err != nil {
			// The Studio file stays in place, so the id is still stable across runs.
			return id
		}
		return stored
	}

	logger.Debug().Msg("machine id: no source produced a value, generating one")
	stored, err := writeSharedFileID(paths, generate(), string(sourceGenerated), writer, logger)
	if err != nil {
		logger.Debug().Msg("machine id: generated value could not be stored, no stable machine id is available")
		return ""
	}
	return stored
}
