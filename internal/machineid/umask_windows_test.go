//go:build windows

package machineid

import "testing"

// withZeroUmask exists only so the shared test file compiles; windows skips the mode test.
func withZeroUmask(t *testing.T) func() {
	t.Helper()
	return func() {}
}
