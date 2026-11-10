// Package subprocess starts child processes without SNYK_ environment variables.
package subprocess

import "strings"

const snykPrefix = "SNYK_"

func cleanEnv(env []string) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		if isSnykEntry(entry) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func isSnykEntry(entry string) bool {
	key, ok := entryKey(entry)
	return ok && hasSnykPrefix(key)
}

func withoutPWD(env []string) []string {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		if key, ok := entryKey(entry); ok && strings.EqualFold(key, "PWD") {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// Windows entries like "=C:=C:\dir" begin with '=', so the search starts at index 1.
func entryKey(entry string) (string, bool) {
	if len(entry) < 2 {
		return "", false
	}
	i := strings.IndexByte(entry[1:], '=')
	if i < 0 {
		return "", false
	}
	return entry[:i+1], true
}

func hasSnykPrefix(key string) bool {
	return len(key) >= len(snykPrefix) && strings.EqualFold(key[:len(snykPrefix)], snykPrefix)
}
