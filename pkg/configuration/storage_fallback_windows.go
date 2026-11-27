//go:build windows

package configuration

import (
	"errors"
	"io/fs"

	"golang.org/x/sys/windows"
)

// canFallBack reports whether a refused replacement may be written in place instead: a file another
// process holds open, or one that may not be replaced. A full disk or an I/O error must not be, as the
// in-place write would truncate the file first.
func canFallBack(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
