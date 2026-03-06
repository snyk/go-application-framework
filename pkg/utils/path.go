package utils

import (
	"fmt"
	"path/filepath"
)

// ToRelativeUnixPath returns the relative path from baseDir to absoluteFilePath
// with forward slashes, suitable for cross-platform use (e.g. upload payloads).
func ToRelativeUnixPath(baseDir string, absoluteFilePath string) (string, error) {
	relPath, err := filepath.Rel(baseDir, absoluteFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to compute relative path from %q to %q: %w", baseDir, absoluteFilePath, err)
	}

	return filepath.ToSlash(relPath), nil
}
