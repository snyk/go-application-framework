// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine.
package machineid

import (
	"encoding/json"
	"errors"
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
// id, and later lookups through the same resolver return that id, together with an error for each
// file that exists but could not be read. If no id was found, it returns runtimeinfo.ErrNoMachineID
// joined with those errors and an error describing why a generated id could not be stored; the
// configuration caching does not hold it, so the next lookup tries the disk again.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	o := resolveOptions{shared: defaultSharedFilePaths(), studio: defaultStudioDeviceIDPaths()}
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	r := &resolver{opts: o}
	return func(_ configuration.Configuration, existingValue any) (any, error) {
		if machine, ok := supplied(existingValue, o.logger); ok {
			return machine, nil
		}
		return r.resolve()
	}
}

// supplied returns a machine set on MACHINE_ID. Strings (env vars, flags, config files) are Machine.ID;
// a JSON object string is the whole machine. runtimeinfo.Machine or *runtimeinfo.Machine is kept.
func supplied(value any, logger *zerolog.Logger) (runtimeinfo.Machine, bool) {
	switch v := value.(type) {
	case runtimeinfo.Machine:
		return suppliedMachine(v, logger)
	case *runtimeinfo.Machine:
		if v == nil {
			return runtimeinfo.Machine{}, false
		}
		return suppliedMachine(*v, logger)
	case string:
		return suppliedString(v, logger)
	default:
		return runtimeinfo.Machine{}, false
	}
}

// Debug, not Warn: this runs on every read, so a bad value would otherwise warn on each one.
func ignoreSupplied(logger *zerolog.Logger, reason string) (runtimeinfo.Machine, bool) {
	logger.Debug().Str("reason", reason).Msg("machine id: supplied value failed validation, ignoring")
	return runtimeinfo.Machine{}, false
}

func suppliedMachine(m runtimeinfo.Machine, logger *zerolog.Logger) (runtimeinfo.Machine, bool) {
	m.ID = strings.TrimRightFunc(m.ID, unicode.IsSpace)
	if blank(m.ID) {
		return ignoreSupplied(logger, "no usable id")
	}
	if reason, ok := validate(m.ID); !ok {
		return ignoreSupplied(logger, reason)
	}
	return m, true
}

func suppliedString(raw string, logger *zerolog.Logger) (runtimeinfo.Machine, bool) {
	raw = strings.TrimRightFunc(raw, unicode.IsSpace)
	if blank(raw) {
		return runtimeinfo.Machine{}, false
	}

	candidate := strings.TrimLeftFunc(raw, unicode.IsSpace)
	if strings.HasPrefix(candidate, "{") {
		var m runtimeinfo.Machine
		if err := json.Unmarshal([]byte(candidate), &m); err != nil {
			return ignoreSupplied(logger, "not valid JSON")
		}
		return suppliedMachine(m, logger)
	}

	return suppliedMachine(runtimeinfo.Machine{ID: raw}, logger)
}

type resolver struct {
	opts resolveOptions

	mu sync.Mutex
	id string
	// readErr is kept with id so every lookup returns the same pair, not only the first.
	readErr error
	// warnedUnstored records that the warning about an unstorable id was logged, so retries log at Debug.
	warnedUnstored bool
}

// resolve returns the id from disk, keeping a found id for the life of the resolver. An empty result
// is not kept, so the next lookup goes back to disk once the cause (a held lock, a missing
// permission) has cleared.
func (r *resolver) resolve() (runtimeinfo.Machine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.id == "" {
		r.id, r.readErr = r.resolveFromDisk()
	}
	if r.id == "" && r.readErr != nil {
		return runtimeinfo.Machine{}, errors.Join(runtimeinfo.ErrNoMachineID, r.readErr)
	}
	if r.id == "" {
		return runtimeinfo.Machine{}, runtimeinfo.ErrNoMachineID
	}
	return runtimeinfo.Machine{ID: r.id}, r.readErr
}

func (r *resolver) resolveFromDisk() (string, error) {
	logger := r.opts.logger
	writer := writerIdentity(r.opts)
	paths := r.opts.shared

	sf, sharedReadErr := readSharedFile(paths, logger)
	if sf != nil {
		logger.Debug().Msg("machine id: adopting value from shared file")
		return sf.MachineID, sharedReadErr
	}

	id, path, ok, studioReadErr := readStudioDeviceID(r.opts.studio, logger)
	readErr := errors.Join(sharedReadErr, studioReadErr)
	if ok {
		logger.Debug().Str("path", path).Msg("machine id: adopting value from Snyk Studio device-id file")
		stored, err := writeSharedFileID(paths, id, string(sourcePersisted), writer, logger)
		if err != nil {
			// The Studio file stays in place, so the id is still stable across runs.
			logger.Debug().Err(err).Msg("machine id: Snyk Studio value could not be stored in the shared file, using it directly")
			return id, readErr
		}
		return stored, readErr
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
		return "", errors.Join(readErr, notPersistedError(err))
	}
	return stored, readErr
}
