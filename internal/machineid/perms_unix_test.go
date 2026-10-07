//go:build !windows

package machineid

import (
	"os"
	"sync"
	"syscall"
	"testing"
)

// withZeroUmask stops the host umask from masking the mode bits under test.
func withZeroUmask(t *testing.T) func() {
	t.Helper()
	old := syscall.Umask(0)
	return func() { syscall.Umask(old) }
}

func makeUnreadable(t *testing.T, path string) (restore func()) {
	t.Helper()
	return restrict(t, path, 0o000, 0o600, func() error { return probeRead(path) })
}

func makeUnwritable(t *testing.T, dir string) {
	t.Helper()
	restrict(t, dir, 0o555, 0o755, func() error { return probeWrite(dir) })
}

func restrict(t *testing.T, path string, mode, restoreMode os.FileMode, probe func() error) func() {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	restore := sync.OnceFunc(func() { _ = os.Chmod(path, restoreMode) }) //nolint:errcheck // best-effort restore so t.TempDir can clean up
	t.Cleanup(restore)
	skipIfStillAccessible(t, probe)
	return restore
}
