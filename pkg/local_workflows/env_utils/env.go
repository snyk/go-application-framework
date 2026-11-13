// Package env_utils provides helpers for preparing child-process environments.
package env_utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

const snykPrefix = "SNYK_"

// SanitizeEnv returns a copy of env without SNYK_ variables, ignoring case. A nil env gives an empty result.
// Unless dir is empty or the platform is windows or plan9, PWD is set to the absolute path of dir.
// It returns an error if dir cannot be resolved.
// It does not read the process environment, but a relative dir resolves against the working directory.
// It only removes the SNYK_ prefix, so other credentials such as NPM_TOKEN pass through. Callers must opt in by calling it.
func SanitizeEnv(env []string, dir string) ([]string, error) {
	result := withoutEntries(env, isSnykEntry)
	if dir == "" || runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		return result, nil
	}
	pwd, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve working directory for %q: %w", dir, err)
	}
	return append(withoutEntries(result, isPWDEntry), "PWD="+pwd), nil
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
