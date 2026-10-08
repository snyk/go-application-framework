// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine.
package machineid

import (
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"

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

// Resolve returns a configuration.DefaultValueFunction for configuration.MACHINE_ID. The first
// lookup takes the first of: a valid value supplied on MACHINE_ID itself, the shared file, the Snyk
// Studio device-id file, or a newly generated id. Later lookups through the same resolver return
// that id, so a value must be supplied before the machine id is first read. If no id was found, it
// returns an empty id with runtimeinfo.ErrNoMachineID, which configuration caching does not hold, so
// a value supplied later is used on the next lookup and the disk is tried again after retryDelay.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	o := resolveOptions{shared: defaultSharedFilePaths(), studio: defaultStudioDeviceIDPaths(), now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	r := &resolver{opts: o}
	return func(_ configuration.Configuration, supplied any) (any, error) {
		if id := r.resolve(supplied); id != "" {
			return id, nil
		}
		return "", runtimeinfo.ErrNoMachineID
	}
}

// retryDelay is how long a resolver waits after failing to get an id before trying again.
const retryDelay = 30 * time.Second

type resolver struct {
	opts resolveOptions

	mu          sync.Mutex
	id          string
	nextAttempt time.Time
	// rejected is the last supplied value that failed validation, so it is logged only once.
	rejected string
	// warnedUnstored records that the warning about an unstorable id was logged, so retries log at Debug.
	warnedUnstored bool
}

func (r *resolver) resolve(supplied any) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A found id is kept for the life of the resolver. A supplied value needs no disk access, so it
	// is used as soon as it appears. An empty result is not kept, so a lookup after retryDelay goes
	// back to disk once the cause (a held lock, a missing permission) has cleared.
	if r.id == "" {
		r.id = r.resolveSupplied(supplied)
	}
	if r.id == "" && !r.opts.now().Before(r.nextAttempt) {
		r.id = r.resolveFromDisk()
		if r.id == "" {
			r.nextAttempt = r.opts.now().Add(retryDelay)
		}
	}
	return r.id
}

// resolveSupplied returns a valid id supplied on MACHINE_ID (set directly, through its environment
// variable, a bound flag or a config file). It is never written to the shared file, so it cannot
// replace the id other Snyk products share.
func (r *resolver) resolveSupplied(supplied any) string {
	raw, _ := supplied.(string) //nolint:errcheck // a non-string value counts as not supplied
	// Trimmed like the Snyk Studio file, so a trailing newline from an environment variable is not fatal.
	raw = strings.TrimRightFunc(raw, unicode.IsSpace)
	if blank(raw) {
		return ""
	}
	reason, ok := validate(raw)
	if !ok {
		if raw != r.rejected {
			r.rejected = raw
			r.opts.logger.Warn().Str("reason", reason).Msg("machine id: supplied value failed validation, ignoring")
		}
		return ""
	}
	r.opts.logger.Debug().Msg("machine id: adopting supplied value")
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
		event := logger.Debug()
		if !r.warnedUnstored {
			r.warnedUnstored = true
			event = logger.Warn()
		}
		event.Err(err).Msg("machine id: generated value could not be stored, no stable machine id is available")
		return ""
	}
	return stored
}
