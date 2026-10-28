//go:build windows

package machineid

import (
	"os"
	"syscall"
)

// openIDFile shares delete as well as read and write. Replacing the file renames over it, and that
// rename fails with a sharing violation while a reader holds a handle without FILE_SHARE_DELETE.
// FILE_FLAG_BACKUP_SEMANTICS keeps a directory openable so it is rejected as not a regular file.
func openIDFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
