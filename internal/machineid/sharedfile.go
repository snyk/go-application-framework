package machineid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/fileperms"
)

var nopLogger = zerolog.Nop()

func effectiveLogger(logger *zerolog.Logger) *zerolog.Logger {
	if logger == nil {
		return &nopLogger
	}
	return logger
}

const (
	sharedFileName      = "machine-id.json"
	sharedSchemaVersion = 1
	lockRetryDelay      = 100 * time.Millisecond
)

// lockTimeout bounds the wait for each shared file location's lock.
var lockTimeout = 1 * time.Second

// sharedFile holds the fields GAF reads or writes. A rewrite marshals exactly these fields (keeping
// first_seen_at), so any field another product added is dropped. Only GAF takes the lock next to the
// file, so another product's writer can race the rewrite. schema_version is the only guard: a writer
// that adds fields must bump it past sharedSchemaVersion, which makes GAF leave the file unchanged.
type sharedFile struct {
	MachineID        string `json:"machine_id"`
	IdentifierSource string `json:"identifier_source"`
	SchemaVersion    int    `json:"schema_version"`
	Scope            string `json:"scope"`
	FirstSeenAt      string `json:"first_seen_at"`
	UpdatedAt        string `json:"updated_at"`
	Writer           string `json:"writer"`

	replaceable bool
}

type pathPair struct {
	machineWide string
	perUser     string
}

// absOrEmpty drops a path built from an unset base location, which would otherwise resolve
// against the working directory.
func absOrEmpty(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return ""
}

func defaultSharedFilePaths() pathPair {
	return sharedFilePathsFor(runtime.GOOS)
}

func sharedFilePathsFor(goos string) pathPair {
	if goos == "windows" {
		return pathPair{
			machineWide: absOrEmpty(filepath.Join(os.Getenv("ProgramData"), "Snyk", sharedFileName)),
			perUser:     absOrEmpty(filepath.Join(os.Getenv("LOCALAPPDATA"), "Snyk", sharedFileName)),
		}
	}
	machineWide := "/etc/snyk/" + sharedFileName
	if goos == "darwin" {
		machineWide = "/Library/Application Support/Snyk/" + sharedFileName
	}
	home, _ := os.UserHomeDir() //nolint:errcheck // an unset home yields no per-user candidate
	return pathPair{
		machineWide: machineWide,
		perUser:     absOrEmpty(filepath.Join(home, ".snyk", sharedFileName)),
	}
}

// readSharedFile returns the first shared file holding a valid id, and an error for each file before
// it that exists but could not be read.
func readSharedFile(paths pathPair, logger *zerolog.Logger) (*sharedFile, error) {
	logger = effectiveLogger(logger)
	var readErrs []error
	for _, c := range paths.scoped() {
		if c.path == "" {
			continue
		}
		sf, err := loadSharedFile(c.path)
		if err == nil {
			return sf, errors.Join(readErrs...)
		}
		logger.Debug().Err(err).Str("path", c.path).Msg("machine id: skipping shared file")
		readErrs = append(readErrs, unreadableFileError(err, sourceSharedFile, c))
	}
	return nil, errors.Join(readErrs...)
}

var (
	errNoValidID   = errors.New("shared file holds no valid machine id")
	errNewerSchema = errors.New("shared file was written by a newer or unknown schema")
)

func loadSharedFile(path string) (*sharedFile, error) {
	data, err := readIDFile(path)
	if errors.Is(err, errFileTooLarge) {
		// No real shared file is this large, so treat it like any other broken file and replace it.
		return nil, fmt.Errorf("%w: %w", errNoValidID, err)
	}
	if err != nil {
		return nil, err
	}
	var sf sharedFile
	var typeErr *json.UnmarshalTypeError
	// A field of the wrong type still fills machine_id. A non-object leaves it blank.
	if err := json.Unmarshal(data, &sf); err != nil && !errors.As(err, &typeErr) {
		return nil, fmt.Errorf("%w: %w", errNoValidID, err)
	}
	var version struct {
		SchemaVersion json.RawMessage `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &version); err != nil {
		return nil, fmt.Errorf("%w: %w", errNoValidID, err)
	}
	sf.replaceable = schemaReplaceable(version.SchemaVersion)
	if !valid(sf.MachineID) {
		return &sf, errNoValidID
	}
	return &sf, nil
}

// schemaReplaceable reports whether a shared file's schema_version is one this code can replace: a
// missing or integer version of 1 or older. A newer, non-integer or unparseable version is left alone
// because its writer may store fields this code would drop.
func schemaReplaceable(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var version int
	if err := json.Unmarshal(raw, &version); err != nil {
		return false
	}
	return version <= sharedSchemaVersion
}

// writeSharedFileID returns the id actually stored, which is an existing valid id when there is one.
// It never creates the machine-wide directory; any failure there falls back to the per-user path, except errNewerSchema, which is returned at once so a newer-schema file is not shadowed.
func writeSharedFileID(paths pathPair, candidateID, source, writer string, logger *zerolog.Logger) (string, error) {
	id, failures := storeSharedFileID(paths, candidateID, source, writer, logger)
	errs := make([]error, 0, len(failures))
	for _, f := range failures {
		errs = append(errs, f.err)
	}
	return id, errors.Join(errs...)
}

// storeSharedFileID is writeSharedFileID reporting each location's failure with its own path.
func storeSharedFileID(paths pathPair, candidateID, source, writer string, logger *zerolog.Logger) (string, []replaceFailure) {
	logger = effectiveLogger(logger)
	var failures []replaceFailure
	if paths.machineWide != "" {
		id, err := writeAt(paths.machineWide, "machine", fileperms.FILEPERM_644, candidateID, source, writer, false, true)
		if err == nil {
			return id, nil
		}
		failures = append(failures, replaceFailure{paths.machineWide, err})
		if errors.Is(err, errNewerSchema) {
			return "", failures
		}
		logger.Debug().Err(err).Str("path", paths.machineWide).Msg("machine id: machine-wide write failed, falling back to per-user")
	}
	id, err := writePerUser(paths.perUser, candidateID, source, writer)
	if err != nil {
		return "", append(failures, replaceFailure{paths.perUser, err})
	}
	return id, nil
}

type replaceFailure struct {
	path string
	err  error
}

// replaceSharedFileID stores candidateID in the machine-wide file, best effort: a different valid id there
// is replaced, and a missing file is created when its directory exists. A per-user file holding a different valid id is replaced
// too, but never created. A file that cannot be replaced is left unchanged and reported in the result.
func replaceSharedFileID(paths pathPair, candidateID, source, writer string) []replaceFailure {
	var failures []replaceFailure
	if paths.machineWide != "" {
		if _, err := writeAt(paths.machineWide, "machine", fileperms.FILEPERM_644, candidateID, source, writer, true, true); err != nil {
			failures = append(failures, replaceFailure{paths.machineWide, err})
		}
	}
	return append(failures, replacePerUserID(paths, candidateID, source, writer)...)
}

func replacePerUserID(paths pathPair, candidateID, source, writer string) []replaceFailure {
	if !perUserHoldsOtherID(paths, candidateID) {
		return nil
	}
	if _, err := writeAt(paths.perUser, "user", fileperms.FILEPERM_600, candidateID, source, writer, true, false); err != nil {
		return []replaceFailure{{paths.perUser, err}}
	}
	return nil
}

func perUserHoldsOtherID(paths pathPair, candidateID string) bool {
	if paths.perUser == "" {
		return false
	}
	existing, err := loadSharedFile(paths.perUser)
	return err == nil && existing.MachineID != candidateID
}

func writePerUser(path, candidateID, source, writer string) (string, error) {
	if path == "" {
		return "", errors.New("machine id: no per-user shared file path")
	}
	if err := os.MkdirAll(filepath.Dir(path), fileperms.FILEPERM_755); err != nil {
		return "", err
	}
	return writeAt(path, "user", fileperms.FILEPERM_600, candidateID, source, writer, false, true)
}

func settled(existing *sharedFile, err error, candidateID string, replace bool) bool {
	return err == nil && (!replace || existing.MachineID == candidateID)
}

// firstSeenAt keeps the first-seen time of a valid id being replaced, so replacing an id does not reset it.
func firstSeenAt(existing *sharedFile, err error, stamp string) string {
	if err == nil && existing.FirstSeenAt != "" {
		return existing.FirstSeenAt
	}
	return stamp
}

// blockedByNewerSchema reports whether the file was written by a schema this code must not overwrite,
// even when its id is invalid. Checked before taking the lock too, so a lock that cannot be created
// does not turn into a per-user shadow file.
func blockedByNewerSchema(existing *sharedFile) bool {
	return existing != nil && !existing.replaceable
}

func writeAt(path, scope string, mode fs.FileMode, candidateID, source, writer string, replace, create bool) (string, error) {
	// Read before locking: the lock file cannot be created in a directory this process cannot write.
	existing, err := loadSharedFile(path)
	if settled(existing, err, candidateID, replace) {
		return existing.MachineID, nil
	}
	if blockedByNewerSchema(existing) {
		return "", errNewerSchema
	}
	lock := flock.New(path + ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	if _, lockErr := lock.TryLockContext(ctx, lockRetryDelay); lockErr != nil {
		// A slow writer may have stored an id while this process waited; use it rather than fail.
		current, currentErr := loadSharedFile(path)
		if settled(current, currentErr, candidateID, replace) {
			return current.MachineID, nil
		}
		if blockedByNewerSchema(current) {
			return "", errNewerSchema
		}
		return "", fmt.Errorf("locking %s: %w", lock.Path(), lockErr)
	}
	defer func() { _ = lock.Unlock() }() //nolint:errcheck // nothing to do about a failed unlock

	// Only a missing or invalid file is replaced; a file that cannot be read is an error, never clobbered.
	existing, err = loadSharedFile(path)
	if settled(existing, err, candidateID, replace) {
		return existing.MachineID, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNoValidID) {
		return "", err
	}
	if errors.Is(err, fs.ErrNotExist) && !create {
		return "", err
	}
	if blockedByNewerSchema(existing) {
		return "", errNewerSchema
	}

	stamp := time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(sharedFile{
		MachineID:        candidateID,
		IdentifierSource: source,
		SchemaVersion:    sharedSchemaVersion,
		Scope:            scope,
		FirstSeenAt:      firstSeenAt(existing, err, stamp),
		UpdatedAt:        stamp,
		Writer:           writer,
	})
	if err != nil {
		return "", err
	}
	if err := renameIntoPlace(path, data, mode); err != nil {
		return "", err
	}
	return candidateID, nil
}

// renameIntoPlace swaps path for data in one rename. Readers take no lock, so the file is never
// rewritten in place.
func renameIntoPlace(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".machine-id-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(data)
	if err == nil {
		// Without the sync, a power loss after the rename can leave an empty file that reads as no id.
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), mode)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	return err
}
