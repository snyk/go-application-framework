//go:build windows

package osname

import "golang.org/x/sys/windows"

// verNTWorkstation is VER_NT_WORKSTATION from winnt.h, which golang.org/x/sys/windows doesn't define.
const verNTWorkstation = 1

func detect() string {
	// GetVersionEx is capped by the application manifest; RtlGetVersion reports the real version.
	info := windows.RtlGetVersion()
	return windowsName(info.MajorVersion, info.MinorVersion, info.BuildNumber, info.ProductType == verNTWorkstation)
}
