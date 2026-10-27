//go:build !windows

package configuration

// osResolveTarget keeps ".." for the kernel, which applies it after following the symlink before it.
func osResolveTarget(target string) string {
	return target
}
