package machineid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/fileperms"
)

// schemaVersion is the current shape of the shared machine-identity file.
const schemaVersion = 1

const (
	scopeMachine = "machine"
	scopeUser    = "user"
)

// defaultWriterIdentity is recorded as the writer field when Resolve was called without
// WithRuntimeInfo, e.g. by a consumer that predates that option or by a test.
const defaultWriterIdentity = "go-application-framework"

// sharedFile is the schema of the machine-identity file shared by every Snyk product on the
// machine. GAF always writes machine_id, identifier_source, schema_version, scope,
// first_seen_at, updated_at and writer; it also writes serial_number and hostname when Resolve
// is called with WithHardwareIdentity and a value was read. snyk_machine_id may be populated by
// other tooling and is preserved, not interpreted, by GAF.
type sharedFile struct {
	MachineID        string `json:"machine_id"`
	IdentifierSource string `json:"identifier_source"`
	SerialNumber     string `json:"serial_number,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	SnykMachineID    string `json:"snyk_machine_id,omitempty"`
	SchemaVersion    int    `json:"schema_version,omitempty"`
	Scope            string `json:"scope,omitempty"`
	FirstSeenAt      string `json:"first_seen_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
	Writer           string `json:"writer,omitempty"`
}

// pathPair is the machine-wide and per-user candidate locations for a file this package reads.
type pathPair struct {
	machineWide string
	perUser     string
}

// sharedFilePaths is a variable so tests can point it at temporary directories; the machine-wide
// path on Linux and macOS is a fixed OS path that a test process cannot write to without root.
var sharedFilePaths = defaultSharedFilePaths

// now is a variable so tests can freeze the timestamps this package stamps into the shared file.
var now = time.Now

// absOrEmpty returns p, or "" if p is not an absolute path. A relative path would resolve
// differently depending on the process's working directory, so any candidate built from an OS
// value that turned out empty (ProgramData/LOCALAPPDATA unset, or os.UserHomeDir failing) is
// discarded rather than used as-is; callers already treat "" as "no candidate here".
func absOrEmpty(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return ""
}

// perUserDir returns the product-neutral per-user directory the shared file and its lock live in.
// It is shared by macOS and Linux; Windows uses %LOCALAPPDATA% instead.
func perUserDir(home string) string {
	return filepath.Join(home, ".snyk")
}

func defaultSharedFilePaths() pathPair {
	switch runtime.GOOS {
	case "windows":
		return pathPair{
			machineWide: absOrEmpty(filepath.Join(os.Getenv("ProgramData"), "Snyk", "machine-id.json")),
			perUser:     absOrEmpty(filepath.Join(os.Getenv("LOCALAPPDATA"), "Snyk", "machine-id.json")),
		}
	case "darwin":
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home is handled by absOrEmpty below
		return pathPair{
			machineWide: "/Library/Application Support/Snyk/machine-id.json",
			perUser:     absOrEmpty(filepath.Join(perUserDir(home), "machine-id.json")),
		}
	default:
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home is handled by absOrEmpty below
		return pathPair{
			machineWide: "/etc/snyk/machine-id.json",
			perUser:     absOrEmpty(filepath.Join(perUserDir(home), "machine-id.json")),
		}
	}
}

// readSharedFile reads the first of the machine-wide or per-user candidates that actually carries a
// valid machine id, machine-wide taking precedence. A candidate that is missing, unparsable, carries
// no machine_id, or carries one that fails validation is skipped rather than treated as the answer,
// so it cannot shadow a later candidate that does hold a usable shared id.
func readSharedFile(paths pathPair, logger *zerolog.Logger) *sharedFile {
	logger = effectiveLogger(logger)
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			logger.Debug().Err(err).Str("path", p).Msg("machine id: shared file candidate could not be read")
			continue
		}
		var sf sharedFile
		if err := json.Unmarshal(data, &sf); err != nil {
			logger.Debug().Err(err).Str("path", p).Msg("machine id: shared file candidate failed to parse")
			continue
		}
		if blank(sf.MachineID) {
			logger.Debug().Str("path", p).Msg("machine id: shared file candidate parsed but carried no machine id")
			continue
		}
		if !valid(sf.MachineID) {
			logger.Debug().Str("path", p).Str("reason", invalidReason(sf.MachineID)).Msg("machine id: shared file candidate failed validation")
			continue
		}
		logger.Debug().Str("path", p).Msg("machine id: shared file candidate carries a machine id")
		return &sf
	}
	return nil
}

// dirWritable reports whether the current process can create files in dir, without leaving one
// behind. os.CreateTemp gives each call a unique probe name, unlike naming the probe after the
// PID alone, which is not unique within a process and races concurrent callers on O_EXCL and on
// the following os.Remove; os.CreateTemp is also more reliable than os.OpenFile on Windows, where
// directory permission bits are not enforced but ACLs are (see the matching probe in
// pkg/local_workflows/doctor_workflow/livecheck/cache/cache.go).
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".snyk-write-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// selectWritePath picks the machine-wide path when its directory already exists and is writable
// by the current process, otherwise the per-user path. On every platform but Windows it never
// creates the machine-wide directory: doing so would require privileges this process may not
// have, and creating it unprivileged is exactly the risk secureDir exists to close on the one
// platform (Windows) where an unprivileged process can otherwise pre-seed it.
func selectWritePath(paths pathPair, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	if paths.machineWide != "" {
		dir := filepath.Dir(paths.machineWide)
		if info, err := os.Stat(dir); err == nil && info.IsDir() && dirWritable(dir) {
			logger.Debug().Str("path", paths.machineWide).Str("scope", scopeMachine).Msg("machine id: machine-wide shared file directory is writable, writing there")
			return paths.machineWide
		}
		if runtime.GOOS == "windows" {
			if mkdirErr := os.MkdirAll(dir, fileperms.FILEPERM_755); mkdirErr == nil {
				if secureErr := secureDir(dir); secureErr != nil {
					logger.Debug().Err(secureErr).Str("path", dir).Msg("machine id: failed to lock down machine-wide shared file directory ACL, not using it")
				} else if dirWritable(dir) {
					logger.Debug().Str("path", paths.machineWide).Str("scope", scopeMachine).Msg("machine id: created and ACL-locked machine-wide shared file directory, writing there")
					return paths.machineWide
				}
			} else {
				logger.Debug().Err(mkdirErr).Str("path", dir).Msg("machine id: could not create machine-wide shared file directory")
			}
		}
	}
	logger.Debug().Str("path", paths.perUser).Str("scope", scopeUser).Msg("machine id: machine-wide shared file directory unavailable, writing to per-user path")
	return paths.perUser
}

// acquireSharedFileLock locks path+".lock", bounded by lockTimeout so a holder that never releases
// it cannot block a writer forever, and returns a function that releases it.
func acquireSharedFileLock(path string, logger *zerolog.Logger) (unlock func(), err error) {
	lock := flock.New(path + ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	locked, lockErr := lock.TryLockContext(ctx, lockRetryDelay)
	if lockErr != nil {
		logger.Debug().Err(lockErr).Str("path", path).Msg("machine id: failed to acquire shared file lock")
		return nil, lockErr
	}
	if !locked {
		logger.Debug().Str("path", path).Msg("machine id: timed out waiting for shared file lock")
		return nil, fmt.Errorf("timed out after %s waiting for lock on %s", lockTimeout, lock.Path())
	}
	return func() { _ = lock.Unlock() }, nil //nolint:errcheck // unlock errors are ignored; nothing actionable can be done with a failed unlock here
}

// mergeKnownSharedFileFields marshals sf and overlays its fields onto existingRaw, so a key this
// package does not model (populated by other Snyk products, or a future schema version) survives a
// write instead of being silently dropped by round-tripping through the sharedFile struct alone.
func mergeKnownSharedFileFields(sf sharedFile, existingRaw map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	knownJSON, err := json.Marshal(sf)
	if err != nil {
		return nil, err
	}
	var known map[string]json.RawMessage
	if err := json.Unmarshal(knownJSON, &known); err != nil {
		return nil, err
	}
	for k, v := range known {
		existingRaw[k] = v
	}
	return existingRaw, nil
}

// writeSharedFileValue serializes writers to path with flock, then applies mutate to the file's
// current contents (or a zero sharedFile if it does not yet exist) and writes back the result.
// createDir controls whether the parent directory may be created, and also which scope is stamped
// into the written file: the machine-wide path's directory is never created here (see
// selectWritePath), so createDir is true exactly when path is the per-user location.
//
// Keys this package does not model (populated by other Snyk products, or by a future schema
// version) are preserved by merging the fields mutate touched on top of the raw JSON object read
// from disk, rather than round-tripping through the sharedFile struct alone, which would silently
// drop any key the struct has no field for.
//
// The result is written to a temp file in the same directory and renamed into place rather than
// truncated and written in place: a reader (readSharedFile uses a bare os.ReadFile, with no lock
// of its own) racing an in-place write could otherwise observe a truncated or partially-written
// file. The rename means every reader sees either the previous complete file or the next one.
func writeSharedFileValue(path string, createDir bool, writer string, mutate func(*sharedFile), logger *zerolog.Logger) error {
	logger = effectiveLogger(logger)
	dir := filepath.Dir(path)
	// The lock file lives next to path, so its directory must exist before flock creates it;
	// MkdirAll has to run before Lock, not after.
	if createDir {
		if err := os.MkdirAll(dir, fileperms.FILEPERM_755); err != nil {
			return err
		}
	}

	unlock, err := acquireSharedFileLock(path, logger)
	if err != nil {
		return err
	}
	defer unlock()

	sf := sharedFile{}
	existingRaw := map[string]json.RawMessage{}
	if data, readErr := os.ReadFile(path); readErr == nil {
		//nolint:errcheck // an unparsable existing file is treated as absent; mutate below fills sf from scratch
		_ = json.Unmarshal(data, &sf)
		//nolint:errcheck // ditto; existingRaw just stays empty, so nothing is preserved from an unparsable file
		_ = json.Unmarshal(data, &existingRaw)
	}

	originalFirstSeenAt := sf.FirstSeenAt
	mutate(&sf)

	sf.SchemaVersion = schemaVersion
	if createDir {
		sf.Scope = scopeUser
	} else {
		sf.Scope = scopeMachine
	}
	if originalFirstSeenAt != "" {
		sf.FirstSeenAt = originalFirstSeenAt
	} else if sf.FirstSeenAt == "" {
		sf.FirstSeenAt = now().UTC().Format(time.RFC3339)
	}
	sf.UpdatedAt = now().UTC().Format(time.RFC3339)
	sf.Writer = writer

	merged, err := mergeKnownSharedFileFields(sf, existingRaw)
	if err != nil {
		return err
	}

	data, err := json.Marshal(merged)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".snyk-machine-id-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below has succeeded

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	mode := fileperms.FILEPERM_644
	if createDir {
		mode = fileperms.FILEPERM_600
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// removeSharedFileValue clears machine_id and identifier_source from the shared file at path,
// leaving any other fields (populated by other tooling, or this package's own metadata fields)
// untouched. A missing file is not an error.
func removeSharedFileValue(path string, writer string, logger *zerolog.Logger) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return writeSharedFileValue(path, false, writer, func(sf *sharedFile) {
		sf.MachineID = ""
		sf.IdentifierSource = ""
	}, logger)
}
