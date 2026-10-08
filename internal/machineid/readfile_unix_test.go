//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package machineid

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mkfifo creates a FIFO with no writer, which a blocking read would wait on forever.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, syscall.Mkfifo(path, 0o600))
}

// withinDeadline fails the test if f does not return promptly, instead of hanging the test run.
func withinDeadline(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked reading a FIFO")
	}
}

func TestReadIDFileRejectsAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	mkfifo(t, path)

	var err error
	withinDeadline(t, func() { _, err = readIDFile(path) })

	require.ErrorIs(t, err, errNotRegularFile)
}

func TestAcceptance_FIFOsAtTheStudioAndSharedFilePathsDoNotHangResolution(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.machineWide, nil)
	writeFile(t, m.shared.perUser, nil)
	for _, p := range []string{m.studio.machineWide, m.shared.perUser} {
		require.NoError(t, syscall.Unlink(p))
		mkfifo(t, p)
	}

	var id string
	withinDeadline(t, func() { id = machineID(t, newRun(t)) })

	require.Empty(t, id, "a FIFO occupies the only writable shared file path, so nothing can be stored")
}
