//go:build windows

package utils

import (
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// availableDiskSpace reports bytes available to the calling user on the volume
// containing path.
//
// GetDiskFreeSpaceEx is used rather than the total-free-bytes value because it
// honours per-user disk quotas, which is what the caller actually has to spend.
func availableDiskSpace(path string) (uint64, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to convert path %s", path)
	}

	var freeBytesAvailableToCaller, totalBytes, totalFreeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(
		pathPtr,
		&freeBytesAvailableToCaller,
		&totalBytes,
		&totalFreeBytes,
	); err != nil {
		return 0, errors.Wrapf(err, "failed to determine available disk space for %s", path)
	}

	return freeBytesAvailableToCaller, nil
}
