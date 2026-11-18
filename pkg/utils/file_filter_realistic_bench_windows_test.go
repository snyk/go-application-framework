package utils

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// processCPUTime returns user plus kernel CPU time for the whole process, across all threads.
func processCPUTime(tb testing.TB) time.Duration {
	tb.Helper()

	var creation, exit, kernel, user windows.Filetime
	require.NoError(tb, windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user))

	return filetimeDuration(kernel) + filetimeDuration(user)
}

// filetimeDuration converts a FILETIME holding a duration, which counts 100 ns units.
func filetimeDuration(ft windows.Filetime) time.Duration {
	return time.Duration(int64(ft.HighDateTime)<<32|int64(ft.LowDateTime)) * 100 * time.Nanosecond
}

// gitMaintenanceProcesses lists running git.exe commands that do maintenance, on any repository: a
// detached maintenance process has no argument that names its repository.
func gitMaintenanceProcesses(tb testing.TB) []string {
	tb.Helper()

	script := `Get-CimInstance Win32_Process -Filter "Name='git.exe'" | ForEach-Object { $_.CommandLine }`
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	require.NoError(tb, err)

	var found []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		for _, word := range []string{" maintenance ", " gc ", " repack ", " pack-objects ", " prune ", " commit-graph ", " multi-pack-index "} {
			if strings.Contains(line+" ", word) {
				found = append(found, line)

				break
			}
		}
	}

	return found
}
