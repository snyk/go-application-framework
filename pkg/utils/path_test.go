package utils

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToRelativeUnixPath(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		abs      string
		expected string
	}{
		{
			name:     "simple relative path",
			base:     filepath.Join("root", "project"),
			abs:      filepath.Join("root", "project", "src", "main.go"),
			expected: "src/main.go",
		},
		{
			name:     "same directory",
			base:     filepath.Join("root", "project"),
			abs:      filepath.Join("root", "project", "file.txt"),
			expected: "file.txt",
		},
		{
			name:     "deeply nested",
			base:     filepath.Join("root"),
			abs:      filepath.Join("root", "a", "b", "c", "d.txt"),
			expected: "a/b/c/d.txt",
		},
		{
			name:     "parent traversal",
			base:     filepath.Join("root", "project", "src"),
			abs:      filepath.Join("root", "project", "docs", "readme.md"),
			expected: "../docs/readme.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToRelativeUnixPath(tt.base, tt.abs)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestToRelativeUnixPath_AlwaysForwardSlashes(t *testing.T) {
	got, err := ToRelativeUnixPath(
		filepath.Join("root", "project"),
		filepath.Join("root", "project", "dir", "file.txt"),
	)
	require.NoError(t, err)
	assert.NotContains(t, got, `\`)
	assert.Equal(t, "dir/file.txt", got)
}
