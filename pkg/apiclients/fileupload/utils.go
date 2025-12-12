package fileupload

import (
	"path/filepath"
	"strings"
)

// updateCommonRoot calculates the lowest common ancestor between the
// current common directory and the new file's directory.
func updateCommonRoot(commonRoot, newFilePath string) string {
	// Get the directory of the new file
	nextDir := filepath.Dir(newFilePath)

	// If this is the first file, return its dir
	if commonRoot == "" {
		return nextDir
	}

	// If they are already the same, no change needed
	if commonRoot == nextDir {
		return commonRoot
	}

	// Shrink commonRoot until it is a prefix of nextDir
	// We check specifically for the separator to avoid partial matches
	for {
		// Calculate the relative path from common to next
		rel, err := filepath.Rel(commonRoot, nextDir)

		// Returning "." is a safe fallback meaning "relative to CWD"
		if err != nil {
			return "."
		}

		// If no error and rel doesn't start with "..", commonRoot is a parent
		if !strings.HasPrefix(rel, "..") {
			return commonRoot
		}

		// Otherwise, move commonRoot up one level
		parent := filepath.Dir(commonRoot)
		// Safety check: if we hit the root ("/" or "."), stop there
		if parent == commonRoot {
			return parent
		}
		commonRoot = parent
	}
}
