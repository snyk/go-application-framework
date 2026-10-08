package machineid

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// maxIDFileSize bounds how much of a machine id file is read. Real files are well under 1 KiB.
const maxIDFileSize = 16 * 1024

var (
	errNotRegularFile = errors.New("not a regular file")
	errFileTooLarge   = errors.New("file too large")
)

// readIDFile reads a small regular file. It opens without blocking, so a FIFO planted at path
// cannot hang the caller, and checks the opened file rather than the path, so the path cannot be
// swapped between the check and the read.
func readIDFile(path string) ([]byte, error) {
	// O_NONBLOCK makes opening a FIFO return at once on macOS and Linux; Windows ignores it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegularFile
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIDFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIDFileSize {
		return nil, errFileTooLarge
	}
	return data, nil
}
