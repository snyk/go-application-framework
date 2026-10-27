//go:build linux

package osname

import (
	"os"
	"strings"
)

var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

const kernelReleasePath = "/proc/sys/kernel/osrelease"

func detect() string {
	for _, path := range osReleasePaths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if name := parseOSRelease(content); name != "" {
			return name
		}
	}

	kernel, err := os.ReadFile(kernelReleasePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace("Linux " + strings.TrimSpace(string(kernel)))
}
