//go:build unix

package machineenrollment

import (
	"os"
	"syscall"
)

// openWithoutBlocking opens path for reading without blocking on a FIFO, so that the caller can
// check the file type before reading.
func openWithoutBlocking(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
