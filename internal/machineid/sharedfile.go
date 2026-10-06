// Package machineid stores a single machine identifier shared by every Snyk product on the same
// machine.
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
	sharedFileName = "machine-id.json"
	lockRetryDelay = 100 * time.Millisecond
)

var lockTimeout = 5 * time.Second

// sharedFile holds the fields GAF reads or writes. Installer-only fields are never carried over,
// because GAF never rewrites a file that holds a valid id.
type sharedFile struct {
	MachineID        string `json:"machine_id"`
	IdentifierSource string `json:"identifier_source"`
	SchemaVersion    int    `json:"schema_version"`
	Scope            string `json:"scope"`
	FirstSeenAt      string `json:"first_seen_at"`
	UpdatedAt        string `json:"updated_at"`
	Writer           string `json:"writer"`
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

func readSharedFile(paths pathPair, logger *zerolog.Logger) *sharedFile {
	logger = effectiveLogger(logger)
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		sf, err := loadSharedFile(p)
		if err == nil {
			return sf
		}
		logger.Debug().Err(err).Str("path", p).Msg("machine id: skipping shared file")
	}
	return nil
}

var errNoValidID = errors.New("shared file holds no valid machine id")

func loadSharedFile(path string) (*sharedFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sf sharedFile
	var typeErr *json.UnmarshalTypeError
	// A field of the wrong type still fills machine_id. A non-object leaves it blank.
	if err := json.Unmarshal(data, &sf); err != nil && !errors.As(err, &typeErr) {
		return nil, fmt.Errorf("%w: %w", errNoValidID, err)
	}
	if !valid(sf.MachineID) {
		return nil, errNoValidID
	}
	return &sf, nil
}

// writeSharedFileID returns the id actually stored, which is an existing valid id when there is one.
// It never creates the machine-wide directory; any failure there falls back to the per-user path.
func writeSharedFileID(paths pathPair, candidateID, source, writer string, logger *zerolog.Logger) (string, error) {
	logger = effectiveLogger(logger)
	var machineWideErr error
	if paths.machineWide != "" {
		id, err := writeAt(paths.machineWide, "machine", fileperms.FILEPERM_644, candidateID, source, writer)
		if err == nil {
			return id, nil
		}
		machineWideErr = err
		logger.Debug().Err(err).Str("path", paths.machineWide).Msg("machine id: machine-wide write failed, falling back to per-user")
	}
	id, err := writePerUser(paths.perUser, candidateID, source, writer)
	if err != nil {
		return "", errors.Join(machineWideErr, err)
	}
	return id, nil
}

func writePerUser(path, candidateID, source, writer string) (string, error) {
	if path == "" {
		return "", errors.New("machine id: no per-user shared file path")
	}
	if err := os.MkdirAll(filepath.Dir(path), fileperms.FILEPERM_755); err != nil {
		return "", err
	}
	return writeAt(path, "user", fileperms.FILEPERM_600, candidateID, source, writer)
}

func writeAt(path, scope string, mode fs.FileMode, candidateID, source, writer string) (string, error) {
	// Read before locking: the lock file cannot be created in a directory this process cannot write.
	if existing, err := loadSharedFile(path); err == nil {
		return existing.MachineID, nil
	}
	lock := flock.New(path + ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	if _, err := lock.TryLockContext(ctx, lockRetryDelay); err != nil {
		return "", fmt.Errorf("locking %s: %w", lock.Path(), err)
	}
	defer func() { _ = lock.Unlock() }() //nolint:errcheck // nothing to do about a failed unlock

	existing, err := loadSharedFile(path)
	if err == nil {
		return existing.MachineID, nil
	}
	if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNoValidID) {
		return "", err
	}

	stamp := time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(sharedFile{
		MachineID:        candidateID,
		IdentifierSource: source,
		SchemaVersion:    1,
		Scope:            scope,
		FirstSeenAt:      stamp,
		UpdatedAt:        stamp,
		Writer:           writer,
	})
	if err != nil {
		return "", err
	}
	// Readers take no lock, so the file is replaced by rename rather than rewritten in place.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".machine-id-*.tmp")
	if err != nil {
		return "", err
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
	if err != nil {
		return "", err
	}
	return candidateID, nil
}
