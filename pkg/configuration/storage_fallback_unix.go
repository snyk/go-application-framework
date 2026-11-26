//go:build unix

package configuration

import (
	"errors"
	"io/fs"
	"syscall"
)

// canFallBack reports whether a refused replacement may be written in place instead: a bind-mounted
// file (EBUSY), a read-only directory or mount, or an immutable file. A full disk or an I/O error
// must not be, as the in-place write would truncate the file first.
func canFallBack(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EBUSY)
}
