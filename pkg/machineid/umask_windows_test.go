//go:build windows

package machineid

import "testing"

// withZeroUmask is a no-op on windows, where the permission-bits test that calls it is skipped
// (permission bits behave differently on windows) but the package must still compile.
func withZeroUmask(t *testing.T) func() {
	t.Helper()
	return func() {}
}
