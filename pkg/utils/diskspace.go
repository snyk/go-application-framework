package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// ErrInsufficientDiskSpace is returned by EnsureFreeDiskSpace when the
// filesystem backing a path has less space available than was requested.
// Callers should surface this distinctly rather than as a generic failure: the
// remedy (free space, or redirect SNYK_TMP_PATH elsewhere) is specific and
// actionable.
type ErrInsufficientDiskSpace struct {
	Path      string
	Requested uint64
	Available uint64
}

func (e *ErrInsufficientDiskSpace) Error() string {
	return fmt.Sprintf(
		"insufficient disk space at %s: %d bytes required, %d bytes available",
		e.Path, e.Requested, e.Available,
	)
}

// AvailableDiskSpace returns the number of bytes available to the current user
// on the filesystem containing path.
//
// If path does not exist yet, its nearest existing ancestor is used, so callers
// can check a directory they are about to create. The value reflects space
// available to an unprivileged user, which on Unix is smaller than the raw free
// space because of the reserved-block allowance.
func AvailableDiskSpace(path string) (uint64, error) {
	existing, err := nearestExistingPath(path)
	if err != nil {
		return 0, err
	}

	return availableDiskSpace(existing)
}

// EnsureFreeDiskSpace returns an *ErrInsufficientDiskSpace if fewer than
// requiredBytes are available on the filesystem containing path.
//
// Note for callers staging many small files: the bytes a payload occupies on
// disk can substantially exceed the sum of its content lengths, because every
// file is rounded up to the filesystem block size. A payload of very many tiny
// files can take more than twice its apparent size. Size the request against
// allocated size, not content size.
func EnsureFreeDiskSpace(path string, requiredBytes uint64) error {
	available, err := AvailableDiskSpace(path)
	if err != nil {
		return err
	}

	if available < requiredBytes {
		return &ErrInsufficientDiskSpace{
			Path:      path,
			Requested: requiredBytes,
			Available: available,
		}
	}

	return nil
}

// nearestExistingPath walks up from path until it finds a path that exists,
// so that a not-yet-created directory can still be measured.
func nearestExistingPath(path string) (string, error) {
	current := filepath.Clean(path)

	for {
		if _, err := os.Stat(current); err == nil {
			return current, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor found for path %s", path)
		}
		current = parent
	}
}
