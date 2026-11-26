//go:build unix

package configuration

import (
	"io/fs"
	"os"
	"syscall"
)

// matchOwner gives the file at path the owner of info, so a configuration file replaced while running
// as root stays readable for its user. Failing is fine: an unprivileged user cannot chown and already
// owns the file.
func matchOwner(path string, info fs.FileInfo) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(stat.Uid), int(stat.Gid)) //nolint:errcheck // Keeping the owner is best effort.
	}
}
