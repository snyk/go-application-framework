// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine.
package machineid

import (
	"strings"
	"sync"
	"time"

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

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID. A value set
// on MACHINE_ID is returned as is. Otherwise the first lookup takes the first of: an id passed in
// by the host (configuration.CLIENT_MACHINE_ID), the shared file, the Snyk Studio device-id file,
// or a newly generated id, and later lookups return that id, so CLIENT_MACHINE_ID must be set
// before the machine id is first read.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	o := resolveOptions{shared: defaultSharedFilePaths(), studio: defaultStudioDeviceIDPaths(), now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	r := &resolver{opts: o}
	return func(config configuration.Configuration, existingValue any) (any, error) {
		if id, ok := existingValue.(string); ok && id != "" {
			return id, nil
		}
		return r.resolve(config), nil
	}
}

// retryDelay is how long a resolver waits after failing to get an id before trying again.
const retryDelay = 30 * time.Second

type resolver struct {
	opts resolveOptions

	mu          sync.Mutex
	id          string
	nextAttempt time.Time
}

func (r *resolver) resolve(config configuration.Configuration) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A found id is kept for the life of the resolver. An empty result is not, so a lookup after
	// retryDelay tries again once the cause (a held lock, a missing permission) has cleared.
	if r.id == "" && !r.opts.now().Before(r.nextAttempt) {
		r.id = r.resolveExplicit(config)
		if r.id == "" {
			r.id = r.resolveFromDisk()
		}
		if r.id == "" {
			r.nextAttempt = r.opts.now().Add(retryDelay)
		}
	}
	return r.id
}

// resolveExplicit returns a valid id passed in by the host. It is never written to the shared
// file, so it cannot replace the id other Snyk products share.
func (r *resolver) resolveExplicit(config configuration.Configuration) string {
	raw := config.GetString(configuration.CLIENT_MACHINE_ID)
	if blank(raw) {
		return ""
	}
	reason, ok := validate(raw)
	if !ok {
		r.opts.logger.Debug().Str("reason", reason).Msg("machine id: external channel value failed validation, ignoring")
		return ""
	}
	r.opts.logger.Debug().Msg("machine id: adopting value from external channel")
	return raw
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
			logger.Debug().Err(err).Msg("machine id: Snyk Studio value could not be stored in the shared file, using it directly")
			return id
		}
		return stored
	}

	logger.Debug().Msg("machine id: no source produced a value, generating one")
	stored, err := writeSharedFileID(paths, generate(), string(sourceGenerated), writer, logger)
	if err != nil {
		logger.Debug().Err(err).Msg("machine id: generated value could not be stored, no stable machine id is available")
		return ""
	}
	return stored
}
