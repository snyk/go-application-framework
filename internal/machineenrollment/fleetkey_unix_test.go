//go:build unix

package machineenrollment

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFleetKeyFileRejectsAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.pem")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	done := make(chan error, 1)
	go func() {
		_, err := ReadFleetKeyFile(path)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFleetKeyFile blocked on a FIFO")
	}
}
