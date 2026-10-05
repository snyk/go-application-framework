//go:build windows

package machineid

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fileDeleteChild is FILE_DELETE_CHILD, which golang.org/x/sys/windows does not define.
const fileDeleteChild = 0x40

const writeAccess = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild | windows.DELETE | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

func usersAccess(t *testing.T, path string) (mask windows.ACCESS_MASK, flags uint8, found bool) {
	t.Helper()
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(dacl, i, &ace))
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(users) {
			continue
		}
		require.Equal(t, uint8(windows.ACCESS_ALLOWED_ACE_TYPE), ace.Header.AceType, "Users must not be named by any ACE other than an allow")
		mask |= ace.Mask
		flags |= ace.Header.AceFlags
		found = true
	}
	return mask, flags, found
}

func TestSecureDirLetsEveryUserReadButNotWriteTheMachineWideFile(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("writing into the locked-down directory requires an elevated administrator token")
	}
	dir := filepath.Join(t.TempDir(), "Snyk")
	require.NoError(t, os.Mkdir(dir, 0o755))

	require.NoError(t, secureDir(dir))
	file := filepath.Join(dir, "machine-id.json")
	for _, id := range []string{"first-id", "second-id"} {
		require.NoError(t, writeSharedFileValue(file, false, "test", func(sf *sharedFile) { sf.MachineID = id }, nil),
			"an administrator must still be able to create and then rewrite the file in the locked-down directory")
	}

	for _, p := range []string{dir, file} {
		mask, _, found := usersAccess(t, p)
		require.True(t, found, "%s: the Users group must be granted access", p)
		require.Equal(t, windows.ACCESS_MASK(windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE), mask&(windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE), "%s: Users must be able to read", p)
		require.Zero(t, mask&writeAccess, "%s: Users must not be able to write", p)
	}
	_, dirFlags, _ := usersAccess(t, dir)
	require.Equal(t, uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE), dirFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE), "the Users ACE must be inherited by the file created in the directory")
}
