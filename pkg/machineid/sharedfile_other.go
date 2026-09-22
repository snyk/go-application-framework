//go:build !windows

package machineid

// secureDir is a no-op outside Windows: on Linux and macOS, selectWritePath only ever writes to
// the machine-wide directory when it already exists (created by package install with the right
// permissions), so this process never creates it and has nothing to lock down.
func secureDir(dir string) error {
	return nil
}
