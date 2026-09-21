//go:build !windows

package machineid

import (
	"syscall"
	"testing"
)

// withZeroUmask clears the process umask for the duration of a test, so an assertion on a written
// file's mode bits reflects exactly what the code requested rather than being coincidentally masked
// down to the same value by the host's default umask.
func withZeroUmask(t *testing.T) func() {
	t.Helper()
	old := syscall.Umask(0)
	return func() { syscall.Umask(old) }
}
