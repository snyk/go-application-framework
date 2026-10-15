// Package machineid resolves and stores a single machine identifier shared by every Snyk product
// on the same machine.
package machineid

import (
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
// or a newly generated id. A valid serial replaces a different id in the shared file. A file written
// by a newer or unknown schema is left unchanged, with a warning. Later lookups through the same resolver return that id,
// together with an error for each file that exists but could not be read. If no id was found, it
// returns runtimeinfo.ErrNoMachineID joined with those errors and an error describing why a
// generated id could not be stored; the configuration caching does not hold it, so the next lookup
// tries the disk again. Machine.StudioID is the INTERNAL_SNYK_CLIENT_MACHINE_ID value when it is
// valid, otherwise the Snyk Studio device-id file; neither supplies the id.
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
	return func(config configuration.Configuration, existingValue any) (any, error) {
		if id, ok := supplied(existingValue, o.logger); ok {
			return r.describe(config, id), nil
		}
		return r.resolve(config)
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

type hardwareIdentity struct {
	hostname string
	serial   string
}

type studioDisk struct {
	id      string
	path    string
	found   bool
	readErr error
}

type resolver struct {
	opts resolveOptions

	hwOnce     sync.Once
	serialOnce sync.Once
	hw         hardwareIdentity

	studioOnce sync.Once
	studio     studioDisk

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

func (r *resolver) studioOnDisk() studioDisk {
	r.studioOnce.Do(func() {
		id, path, found, err := readStudioDeviceID(r.opts.studio, r.opts.logger)
		if err != nil {
			r.opts.logger.Debug().Err(err).Msg("machine id: Snyk Studio device-id file could not be read for the machine description")
		}
		r.studio = studioDisk{id: id, path: path, found: found, readErr: err}
	})
	return r.studio
}

// describe returns the machine with the given id and the descriptive fields that can be read. Read
// failures are not reported: a supplied id needs none of them. Hostname, SerialNumber and StudioID are
// still filled in, because hosts describe the machine even when its id comes from elsewhere.
func (r *resolver) describe(config configuration.Configuration, id string) runtimeinfo.Machine {
	hw := r.hardware()
	disk := r.studioOnDisk()
	return runtimeinfo.Machine{ID: id, Hostname: hw.hostname, SerialNumber: hw.serial, StudioID: studioID(config, r.opts.logger, disk.id)}
}

// resolve returns the id from disk, keeping a found id for the life of the resolver. An empty result
// is not kept, so the next lookup goes back to disk once the cause (a held lock, a missing
// permission) has cleared.
func (r *resolver) resolve(config configuration.Configuration) (runtimeinfo.Machine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.machine.ID == "" {
		m, err := r.resolveFromDisk()
		if m.ID == "" {
			return runtimeinfo.Machine{}, errors.Join(runtimeinfo.ErrNoMachineID, err)
		}
		r.machine, r.readErr = m, err
	}
	machine := r.machine
	machine.StudioID = studioID(config, r.opts.logger, r.studioOnDisk().id)
	return machine, r.readErr
}

func (r *resolver) resolveFromDisk() (runtimeinfo.Machine, error) {
	logger := r.opts.logger
	writer := writerIdentity(r.opts)
	paths := r.opts.shared
	hw := r.hardware()

	disk := r.studioOnDisk()
	diskStudioID, studioPath, studioOK, studioReadErr := disk.id, disk.path, disk.found, disk.readErr
	machine := runtimeinfo.Machine{Hostname: hw.hostname, SerialNumber: hw.serial}

	if hw.serial != "" {
		if reason, ok := validate(hw.serial); !ok {
			logger.Debug().Str("reason", reason).Msg("machine id: hardware serial number failed validation, ignoring")
		} else {
			machine.ID = hw.serial
			existing, sharedReadErr := readSharedFile(paths, logger)
			if existing == nil || existing.MachineID != hw.serial {
				stored, err := replaceSharedFileID(paths, hw.serial, string(sourceSerial), writer, logger)
				switch {
				case errors.Is(err, errNewerSchema):
					logger.Warn().Err(err).Msg("machine id: shared file was written by a newer or unknown schema, left unchanged")
				case err != nil:
					logger.Debug().Err(err).Msg("machine id: serial number could not be stored in the shared file, using it directly")
				default:
					if after, afterErr := readSharedFile(paths, logger); after != nil && after.MachineID != hw.serial {
						event := logger.Warn()
						if isUnfixableLocation(stored.machineWideErr) {
							event = logger.Debug()
						}
						event.Err(afterErr).Str("shared_machine_id", after.MachineID).Msg("machine id: shared file holds a different machine id that could not be replaced by the hardware serial")
					}
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
