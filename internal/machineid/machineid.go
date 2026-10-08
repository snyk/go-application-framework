// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine.
package machineid

import (
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

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

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID. It takes the
// first of: an id passed in by the host (configuration.CLIENT_MACHINE_ID), the shared file, the
// Snyk Studio device-id file, or a newly generated id.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	o := resolveOptions{shared: defaultSharedFilePaths(), studio: defaultStudioDeviceIDPaths()}
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

	// Checked on every lookup, and never written to the shared file, so it cannot replace the id
	// other Snyk products share.
	if raw := config.GetString(configuration.CLIENT_MACHINE_ID); !blank(raw) {
		if valid(raw) {
			logger.Debug().Msg("machine id: adopting value from external channel")
			return raw
		}
		logger.Debug().Str("reason", invalidReason(raw)).Msg("machine id: external channel value failed validation, ignoring")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// A found id is kept for the life of the resolver. An empty result is not, so a later lookup
	// retries once the cause (a held lock, a missing permission) has cleared.
	if r.fromDisk == "" {
		r.fromDisk = r.resolveFromDisk()
	}
	return r.fromDisk
}

func (r *resolver) resolveFromDisk() string {
	logger := r.opts.logger
	writer := writerIdentity(r.opts)
	paths := r.opts.shared

	if sf := readSharedFile(paths, logger); sf != nil {
		logger.Debug().Msg("machine id: adopting value from shared file")
		return sf.MachineID
	}

	if id, path, ok := readStudioDeviceID(r.opts.studio, logger); ok {
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
