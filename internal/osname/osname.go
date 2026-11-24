// Package osname detects the name and version of the operating system the process runs on.
package osname

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"sync"
)

var detectOnce = sync.OnceValue(detect)

// Get returns the operating system name and version, or "" when they can't be detected.
func Get() string {
	return detectOnce()
}

// Windows 11 kept the 10.0 kernel version, so only its build number tells it apart from Windows 10.
const firstWindows11Build = 22000

func windowsName(major, minor, build uint32, workstation bool) string {
	version := fmt.Sprintf("%d.%d.%d", major, minor, build)
	switch {
	case !workstation:
		return "Windows Server " + version
	case major == 10 && build >= firstWindows11Build:
		return "Windows 11 " + version
	case major == 10:
		return "Windows 10 " + version
	default:
		return "Windows " + version
	}
}

func parseOSRelease(content []byte) string {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"'`)
	}

	if values["PRETTY_NAME"] != "" {
		return values["PRETTY_NAME"]
	}
	name, version := values["NAME"], values["VERSION_ID"]
	// os-release(5) defaults a missing NAME to "Linux".
	if name == "" && version != "" {
		name = "Linux"
	}
	return strings.TrimSpace(name + " " + version)
}
