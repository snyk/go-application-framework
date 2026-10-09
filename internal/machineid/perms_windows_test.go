//go:build windows

package machineid

import (
	"os/exec"
	"sync"
	"testing"
)

// withZeroUmask exists only so the shared test file compiles; windows skips the mode test.
func withZeroUmask(t *testing.T) func() {
	t.Helper()
	return func() {}
}

// Narrow rights, not icacls' R or W: those include SYNCHRONIZE, and denying it blocks every open.
func makeUnreadable(t *testing.T, path string) (restore func()) {
	t.Helper()
	return deny(t, path, "(RD)", func() error { return probeRead(path) })
}

func makeUnwritable(t *testing.T, dir string) {
	t.Helper()
	deny(t, dir, "(WD,AD)", func() error { return probeWrite(dir) })
}

func deny(t *testing.T, path, rights string, probe func() error) func() {
	t.Helper()
	icacls(t, path, "/deny", everyoneSID+":"+rights)
	restore := sync.OnceFunc(func() { icacls(t, path, "/remove:d", everyoneSID) })
	t.Cleanup(restore)
	skipIfStillAccessible(t, probe)
	return restore
}

const everyoneSID = "*S-1-1-0"

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v: %s", args, err, out)
	}
}
