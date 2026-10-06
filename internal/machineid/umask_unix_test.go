//go:build !windows

package machineid

import (
	"syscall"
	"testing"
)

// withZeroUmask stops the host umask from masking the mode bits under test.
func withZeroUmask(t *testing.T) func() {
	t.Helper()
	old := syscall.Umask(0)
	return func() { syscall.Umask(old) }
}
