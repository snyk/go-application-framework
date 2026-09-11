package utils

import "path/filepath"

// MakeRelativePathsAbsolute resolves any relative paths in the given slice
// by joining them with baseDirPath. Already-absolute paths are left unchanged.
func MakeRelativePathsAbsolute(baseDirPath string, paths []string) []string {
	result := make([]string, len(paths))
	for i, p := range paths {
		if filepath.IsAbs(p) {
			result[i] = p
		} else {
			result[i] = filepath.Join(baseDirPath, p)
		}
	}
	return result
}
