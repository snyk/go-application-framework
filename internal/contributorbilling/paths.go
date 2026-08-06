package contributorbilling

import "path/filepath"

func resolveRepoPath(path string) string {
	if path == "" {
		path = "."
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}

	return abs
}
