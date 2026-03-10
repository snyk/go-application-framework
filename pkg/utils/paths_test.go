package utils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MakeRelativePathsAbsolute(t *testing.T) {
	baseDir := filepath.Join("/", "home", "user", "project")

	t.Run("resolves relative paths", func(t *testing.T) {
		input := []string{".snyk.env", ".envrc"}
		result := MakeRelativePathsAbsolute(baseDir, input)

		assert.Equal(t, []string{
			filepath.Join(baseDir, ".snyk.env"),
			filepath.Join(baseDir, ".envrc"),
		}, result)
	})

	t.Run("leaves absolute paths unchanged", func(t *testing.T) {
		absPath := filepath.Join("/", "etc", "config.env")
		input := []string{absPath}
		result := MakeRelativePathsAbsolute(baseDir, input)

		assert.Equal(t, []string{absPath}, result)
	})

	t.Run("handles mix of relative and absolute", func(t *testing.T) {
		absPath := filepath.Join("/", "etc", "config.env")
		input := []string{absPath, ".snyk.env"}
		result := MakeRelativePathsAbsolute(baseDir, input)

		assert.Equal(t, []string{
			absPath,
			filepath.Join(baseDir, ".snyk.env"),
		}, result)
	})

	t.Run("returns empty slice for empty input", func(t *testing.T) {
		result := MakeRelativePathsAbsolute(baseDir, []string{})
		assert.Empty(t, result)
	})

	t.Run("returns empty slice for nil input", func(t *testing.T) {
		result := MakeRelativePathsAbsolute(baseDir, nil)
		assert.Empty(t, result)
	})

	t.Run("does not modify original slice", func(t *testing.T) {
		input := []string{".snyk.env", ".envrc"}
		original := make([]string, len(input))
		copy(original, input)

		MakeRelativePathsAbsolute(baseDir, input)

		assert.Equal(t, original, input)
	})
}
