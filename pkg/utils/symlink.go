package utils

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SymlinkError reports that Path, as the caller passed it, is a symbolic link, which Snyk never follows.
type SymlinkError struct {
	Path string
}

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("%s is a symbolic link. Snyk does not follow symbolic links; pass the real path instead.", e.Path)
}

// CheckNotSymlink returns a *SymlinkError if the last element of path is a symbolic link, also when path ends in
// separators or "." elements. Only the last element counts: a path through a symlinked parent folder is allowed.
// A path that cannot be stat'ed, for example because it does not exist, is not reported, as it cannot be read either.
// Windows junctions (mount points) are not symbolic links to Go and are not reported.
func CheckNotSymlink(path string) error {
	if isSymlink(trimTrailingElements(path)) {
		return &SymlinkError{Path: path}
	}
	return nil
}

// trimTrailingElements drops trailing separators and "." elements, because the OS follows a symlink that is
// followed by either when it resolves the path. ".." is kept, since removing it lexically would select another file.
// A filesystem root keeps one separator.
func trimTrailingElements(path string) string {
	separators := "/"
	if filepath.Separator != '/' {
		separators += string(filepath.Separator)
	}
	volume := filepath.VolumeName(path)
	rest := path[len(volume):]
	for {
		trimmed := strings.TrimRight(rest, separators)
		if trimmed == "" {
			return volume + rest[:min(1, len(rest))]
		}
		i := strings.LastIndexAny(trimmed, separators)
		if i < 0 || trimmed[i+1:] != "." {
			return volume + trimmed
		}
		rest = trimmed[:i+1]
	}
}
