//go:build !windows

package machineid

import (
	"os"
	"syscall"
)

// openIDFile opens without blocking, so a FIFO planted at path cannot hang the caller.
func openIDFile(path string) (*os.File, error) {
	// O_NONBLOCK makes opening a FIFO return at once on macOS and Linux.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
