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

	"github.com/snyk/go-application-framework/internal/machineid/identity"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

// idSource records in the shared file how its machine identifier was obtained.
type idSource string

const (
	sourceSerial    idSource = "serial"
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
// lookup takes the first of: the hardware serial, the shared file, the Snyk Studio device-id file,
// or a newly generated id. A different id already in the shared file is not replaced yet, so the
// serial wins only for this process. Later lookups through the same resolver return that id,
// together with an error for each file that exists but could not be read. If no id was found, it
// returns runtimeinfo.ErrNoMachineID joined with those errors and an error describing why a
// generated id could not be stored; the configuration caching does not hold it, so the next lookup
// tries the disk again.
func Resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	o := resolveOptions{
		shared:       defaultSharedFilePaths(),
		studio:       defaultStudioDeviceIDPaths(),
		serialNumber: identity.SerialNumber,
		hostname:     identity.Hostname,
	}
	for _, opt := range opts {
		opt(&o)
	}
	o.logger = effectiveLogger(o.logger)
	r := &resolver{opts: o}
	return func(_ configuration.Configuration, existingValue any) (any, error) {
		if machine, ok := supplied(existingValue, o.logger); ok {
			return r.describe(machine), nil
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

type hardwareIdentity struct {
	hostname string
	serial   string
}

type resolver struct {
	opts resolveOptions

	hwOnce     sync.Once
	serialOnce sync.Once
	hw         hardwareIdentity

	mu      sync.Mutex
	machine runtimeinfo.Machine
	// readErr is kept with id so every lookup returns the same pair, not only the first.
	readErr error
	// warnedUnstored records that the warning about an unstorable id was logged, so retries log at Debug.
	warnedUnstored bool
}

func (r *resolver) hardware() hardwareIdentity {
	r.hwOnce.Do(func() {
		if hostname, err := r.opts.hostname(); err == nil {
			r.hw.hostname = hostname
		}
	})
	r.serialOnce.Do(func() {
		serial, err := r.opts.serialNumber()
		if err != nil {
			r.opts.logger.Debug().Err(err).Msg("machine id: hardware serial number could not be read")
			return
		}
		r.hw.serial = serial
	})
	return r.hw
}

// describe returns the supplied machine with its empty hardware fields filled from what can be read.
// A supplied machine needs none of them, so read failures are not reported, but hosts still describe
// the machine.
func (r *resolver) describe(m runtimeinfo.Machine) runtimeinfo.Machine {
	hw := r.hardware()
	if m.Hostname == "" {
		m.Hostname = hw.hostname
	}
	if m.SerialNumber == "" {
		m.SerialNumber = hw.serial
	}
	return m
}

// resolve returns the id from disk, keeping a found id for the life of the resolver. An empty result
// is not kept, so the next lookup goes back to disk once the cause (a held lock, a missing
// permission) has cleared.
func (r *resolver) resolve() (runtimeinfo.Machine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.machine.ID == "" {
		m, err := r.resolveFromDisk()
		if m.ID == "" {
			return runtimeinfo.Machine{}, errors.Join(runtimeinfo.ErrNoMachineID, err)
		}
		r.machine, r.readErr = m, err
	}
	return r.machine, r.readErr
}

func (r *resolver) resolveFromDisk() (runtimeinfo.Machine, error) {
	logger := r.opts.logger
	writer := writerIdentity(r.opts)
	paths := r.opts.shared
	hw := r.hardware()

	machine := runtimeinfo.Machine{Hostname: hw.hostname, SerialNumber: hw.serial}

	if hw.serial != "" {
		if reason, ok := validate(hw.serial); !ok {
			logger.Debug().Str("reason", reason).Msg("machine id: hardware serial number failed validation, ignoring")
		} else {
			machine.ID = hw.serial
			// Read both scopes first. Nil means neither the machine-wide nor the per-user
			// file holds a valid id, so the serial may be stored. A file that already
			// holds an id is left as it is.
			sf, sharedReadErr := readSharedFile(paths, logger)
			if sf == nil {
				if _, err := writeSharedFileID(paths, hw.serial, string(sourceSerial), writer, logger); err != nil {
					logger.Debug().Err(err).Msg("machine id: serial number could not be stored in the shared file, using it directly")
				}
			}
			return machine, sharedReadErr
		}
	}

	sf, sharedReadErr := readSharedFile(paths, logger)
	if sf != nil {
		logger.Debug().Msg("machine id: adopting value from shared file")
		machine.ID = sf.MachineID
		return machine, sharedReadErr
	}

	diskStudioID, studioPath, studioOK, studioReadErr := readStudioDeviceID(r.opts.studio, logger)
	if studioOK {
		logger.Debug().Str("path", studioPath).Msg("machine id: adopting value from Snyk Studio device-id file")
		readErr := errors.Join(sharedReadErr, studioReadErr)
		machine.ID = diskStudioID
		stored, err := writeSharedFileID(paths, diskStudioID, string(sourcePersisted), writer, logger)
		if err != nil {
			// The Studio file stays in place, so the id is still stable across runs.
			logger.Debug().Err(err).Msg("machine id: Snyk Studio value could not be stored in the shared file, using it directly")
			return machine, readErr
		}
		// A racing write can win, so this is the id actually in the file, not the one just attempted.
		machine.ID = stored
		return machine, readErr
	}

	logger.Debug().Msg("machine id: no source produced a value, generating one")
	readErr := sharedReadErr
	stored, err := writeSharedFileID(paths, generate(), string(sourceGenerated), writer, logger)
	if err != nil {
		const msg = "machine id: generated value could not be stored, no stable machine id is available"
		if r.warnedUnstored {
			logger.Debug().Err(err).Msg(msg)
		} else {
			r.warnedUnstored = true
			logger.Warn().Err(err).Msg(msg)
		}
		return runtimeinfo.Machine{}, errors.Join(readErr, notPersistedError(err))
	}
	machine.ID = stored
	return machine, readErr
}
