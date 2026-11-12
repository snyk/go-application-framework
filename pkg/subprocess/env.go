// Package subprocess starts child processes without SNYK_ environment variables.
package subprocess

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const snykPrefix = "SNYK_"

// SanitizeCmdEnv removes SNYK_ variables from cmd.Env, ignoring case. Call it after setting cmd.Dir and cmd.Env.
// If cmd.Dir is set on platforms other than windows and plan9, PWD is replaced by its absolute path, even if Env had one.
// It returns an error if cmd.Dir cannot be resolved, in which case cmd is unchanged.
// A nil cmd.Env starts from os.Environ(). The process environment is unchanged.
func SanitizeCmdEnv(cmd *exec.Cmd) error {
	if cmd == nil {
		return nil
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	env = withoutEntries(env, isSnykEntry)
	if cmd.Dir != "" && runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
		pwd, err := filepath.Abs(cmd.Dir)
		if err != nil {
			return fmt.Errorf("resolve working directory for %q: %w", cmd.Dir, err)
		}
		env = append(withoutEntries(env, isPWDEntry), "PWD="+pwd)
	}
	cmd.Env = env
	return nil
}

// withoutEntries returns a new slice, so the caller's slice is never modified.
func withoutEntries(env []string, drop func(string) bool) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		if !drop(entry) {
			result = append(result, entry)
		}
	}
	return result
}

// A leading '=' is trimmed first, so "=SNYK_X=v" matches and Windows drive entries like "=C:=C:\dir" do not.
func isSnykEntry(entry string) bool {
	name := strings.TrimPrefix(entry, "=")
	return len(name) >= len(snykPrefix) && strings.EqualFold(name[:len(snykPrefix)], snykPrefix)
}

func isPWDEntry(entry string) bool {
	return strings.HasPrefix(entry, "PWD=")
}
