//go:build windows

package configuration

import "path/filepath"

// osResolveTarget collapses ".." within a link's relative target lexically, as Windows does before it
// follows reparse points inside the target, so the resolver writes where the OS reads. A leading ".."
// survives Clean and still climbs out of the link's already resolved directory.
func osResolveTarget(target string) string {
	return filepath.Clean(target)
}
