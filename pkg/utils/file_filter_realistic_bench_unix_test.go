//go:build unix

package utils

import (
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// processCPUTime returns user plus system CPU time for the whole process, across all threads.
func processCPUTime(tb testing.TB) time.Duration {
	tb.Helper()

	var usage syscall.Rusage
	require.NoError(tb, syscall.Getrusage(syscall.RUSAGE_SELF, &usage))

	return time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond +
		time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
}

var gitMaintenanceCommand = regexp.MustCompile(`(^|/)gitCmd( .*)? (maintenance|gc|repack|pack-objects|prune|commit-graph|multi-pack-index)( |$)`)

// gitMaintenanceProcesses lists running git commands that do maintenance, on any repository: a
// detached maintenance process has no argument that names its repository.
func gitMaintenanceProcesses(tb testing.TB) []string {
	tb.Helper()

	output, err := exec.Command("ps", "-axo", "command=").Output()
	require.NoError(tb, err)

	var found []string
	for _, line := range strings.Split(string(output), "\n") {
		if gitMaintenanceCommand.MatchString(strings.TrimSpace(line)) {
			found = append(found, strings.TrimSpace(line))
		}
	}

	return found
}
