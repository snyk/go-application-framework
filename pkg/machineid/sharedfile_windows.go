//go:build windows

package machineid

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// secureDir replaces dir's DACL with one granting full control to SYSTEM and Administrators only,
// and marks it protected so no ACE inherited from a parent directory carries broader access into
// it. This only matters on Windows: this package creates the machine-wide directory itself only
// on that platform (see selectWritePath), and an unprivileged process could otherwise pre-create
// it with permissions of its own choosing before a privileged installer ever gets to it, letting
// any user on the machine read or overwrite an identifier every product on the machine shares.
func secureDir(dir string) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("resolving SYSTEM sid: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("resolving Administrators sid: %w", err)
	}

	var pinner runtime.Pinner
	pinner.Pin(system)
	pinner.Pin(admins)
	defer pinner.Unpin()

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(admins),
			},
		},
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("building ACL: %w", err)
	}

	return windows.SetNamedSecurityInfo(
		dir,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}
