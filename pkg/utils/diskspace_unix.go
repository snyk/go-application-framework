//go:build !windows

package utils

import (
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// availableDiskSpace reports bytes available to an unprivileged user on the
// filesystem containing path.
//
// Bavail is used rather than Bfree: Bfree includes the blocks reserved for
// root, which a CLI running as a normal user cannot actually use.
func availableDiskSpace(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, errors.Wrapf(err, "failed to determine available disk space for %s", path)
	}

	//nolint:unconvert,gosec // Bsize is int64 on Linux and int32 on Darwin; the conversion is required on one and a no-op on the other.
	return stat.Bavail * uint64(stat.Bsize), nil
}
