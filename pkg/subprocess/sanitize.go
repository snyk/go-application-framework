package subprocess

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// SanitizeEnv returns a copy of env without variables whose names start with any of prefixes, ignoring case.
// Empty prefixes are skipped, and with no prefixes nothing is removed. A nil env gives an empty result.
// Unless dir is empty or the platform is windows or plan9, PWD is set to the absolute path of dir.
// It returns a SNYK-CLI-0039 (ExternalProgramFailed) error if dir cannot be resolved.
// It does not read the process environment, but a relative dir resolves against the working directory.
// Only the given prefixes are removed, so other credentials such as NPM_TOKEN pass through. Callers must opt in by calling it.
// Callers holding a slice of prefixes pass it as prefixes...
func SanitizeEnv(env []string, dir string, prefixes ...string) ([]string, error) {
	lowerPrefixes := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix != "" {
			lowerPrefixes = append(lowerPrefixes, strings.ToLower(prefix))
		}
	}
	result := withoutEntries(env, func(entry string) bool {
		return hasAnyPrefix(entry, lowerPrefixes)
	})
	if dir == "" || runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		return result, nil
	}
	pwd, err := filepath.Abs(dir)
	if err != nil {
		return nil, cli.NewExternalProgramFailedError(fmt.Sprintf("resolve working directory for %q", dir), snyk_errors.WithCause(err))
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
func hasAnyPrefix(entry string, lowerPrefixes []string) bool {
	name := strings.ToLower(strings.TrimPrefix(entry, "="))
	for _, prefix := range lowerPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func isPWDEntry(entry string) bool {
	return strings.HasPrefix(entry, "PWD=")
}
