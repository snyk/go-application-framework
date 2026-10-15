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

func TestWriteSharedFileIDReplacesTheFileWhileAReaderHoldsItOpen(t *testing.T) {
	paths := tempPaths(t)
	seed(t, paths.machineWide, "")
	f, err := openIDFile(paths.machineWide)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	require.Equal(t, "new-id", write(t, paths, "new-id"))

	require.Equal(t, "new-id", readFile(t, paths.machineWide).MachineID)
}
