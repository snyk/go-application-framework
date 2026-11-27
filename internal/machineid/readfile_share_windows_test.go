//go:build windows

package machineid

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

const deleteAccess = 0x00010000

// openWithDeleteAccess holds path open the way a replacing writer does while it renames over it.
func openWithDeleteAccess(t *testing.T, path string) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	require.NoError(t, err)
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ|deleteAccess,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, syscall.CloseHandle(h)) })
}

func TestReadIDFileReadsWhileAnotherHandleHasDeleteAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(path, []byte("an-id"), 0o600))
	openWithDeleteAccess(t, path)

	data, err := readIDFile(path)

	require.NoError(t, err)
	require.Equal(t, "an-id", string(data))
}

func TestWriteSharedFileIDStoresAnIDWhileAReaderHoldsTheMachineWideFileOpen(t *testing.T) {
	paths := tempPaths(t)
	seed(t, paths.machineWide, "")
	openWithDeleteAccess(t, paths.machineWide)

	id, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.NoError(t, err)
	require.Equal(t, "new-id", id)
	require.True(t, valid(id))
	require.True(t, storedIDIn(t, paths, id), "id must be readable from the machine-wide or the per-user file")
}

func storedIDIn(t *testing.T, paths pathPair, id string) bool {
	t.Helper()
	for _, path := range []string{paths.machineWide, paths.perUser} {
		if sf, err := loadSharedFile(path); err == nil && sf.MachineID == id {
			return true
		}
	}
	return false
}
