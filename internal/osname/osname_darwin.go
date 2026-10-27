//go:build darwin

package osname

import "syscall"

func detect() string {
	version, err := syscall.Sysctl("kern.osproductversion")
	if err != nil || version == "" {
		return ""
	}
	return "macOS " + version
}
