// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine.
package machineid

import (
	"strings"
	"sync"
	"unicode"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
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

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID. A valid value
// supplied on MACHINE_ID itself (trailing whitespace trimmed) is returned. Otherwise the first
// lookup takes the first of: the shared file, the Snyk Studio device-id file, or a newly generated
// id, and later lookups through the same resolver return that id. If no id was found, it returns
// runtimeinfo.ErrNoMachineID, which configuration caching does not hold, so the next lookup tries
// the disk again.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	o := resolveOptions{shared: defaultSharedFilePaths(), studio: defaultStudioDeviceIDPaths()}
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	r := &resolver{opts: o}
	return func(_ configuration.Configuration, existingValue any) (any, error) {
		if id, ok := supplied(existingValue, o.logger); ok {
			return id, nil
		}
		return r.resolve()
	}
}

// supplied returns a valid id supplied on MACHINE_ID (set directly, through its environment variable,
// a bound flag or a config file). Trailing whitespace is trimmed, like the Snyk Studio file, so a
// trailing newline from an environment variable is not fatal.
func supplied(value any, logger *zerolog.Logger) (string, bool) {
	raw, _ := value.(string) //nolint:errcheck // a non-string value counts as not supplied
	raw = strings.TrimRightFunc(raw, unicode.IsSpace)
	if blank(raw) {
		return "", false
	}
	if reason, ok := validate(raw); !ok {
		// Debug, not Warn: this runs on every read, so a bad value would otherwise warn on each one.
		logger.Debug().Str("reason", reason).Msg("machine id: supplied value failed validation, ignoring")
		return "", false
	}
	return raw, true
}

type resolver struct {
	opts resolveOptions

	mu sync.Mutex
	id string
	// warnedUnstored records that the warning about an unstorable id was logged, so retries log at Debug.
	warnedUnstored bool
}

// resolve returns the id from disk, keeping a found id for the life of the resolver. An empty result
// is not kept, so the next lookup goes back to disk once the cause (a held lock, a missing
// permission) has cleared.
func (r *resolver) resolve() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.id == "" {
		r.id = r.resolveFromDisk()
	}
	if r.id == "" {
		return "", runtimeinfo.ErrNoMachineID
	}
	return r.id, nil
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
		const msg = "machine id: generated value could not be stored, no stable machine id is available"
		if r.warnedUnstored {
			logger.Debug().Err(err).Msg(msg)
		} else {
			r.warnedUnstored = true
			logger.Warn().Err(err).Msg(msg)
		}
		return ""
	}
	return stored
}
