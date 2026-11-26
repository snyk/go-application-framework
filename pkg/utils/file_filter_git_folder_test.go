package utils

import (
	"path/filepath"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAllFiles_DoesNotEnterGitFolders(t *testing.T) {
	root := t.TempDir()
	createFileInPath(t, filepath.Join(root, ".git", "config"), []byte{})
	createFileInPath(t, filepath.Join(root, "sub", ".git", "HEAD"), []byte{})
	createFileInPath(t, filepath.Join(root, "sub", "a.js"), []byte{})
	createFileInPath(t, filepath.Join(root, ".github", "workflow.yml"), []byte{})
	createFileInPath(t, filepath.Join(root, ".gitignore"), []byte{})
	createFileInPath(t, filepath.Join(root, "a.git", "x.js"), []byte{})

	fileFilter := NewFileFilter(root, &log.Logger)
	filesCh := fileFilter.GetAllFiles()
	got := drainFilteredFiles(t, filesCh)

	expected := []string{
		filepath.Join(root, "sub", "a.js"),
		filepath.Join(root, ".github", "workflow.yml"),
		filepath.Join(root, ".gitignore"),
		filepath.Join(root, "a.git", "x.js"),
	}
	assert.ElementsMatch(t, expected, got)
}

func TestGetFilteredFiles_NeverReturnsGitFolderFiles(t *testing.T) {
	root := t.TempDir()
	inputs := []string{
		filepath.Join(root, ".git", "config"),
		filepath.Join(root, ".git"),
		filepath.Join(root, "sub", ".git"),
		filepath.Join(root, "sub", ".git", "HEAD"),
		filepath.Join(root, ".github", "x.yml"),
		filepath.Join(root, "a.git", "x.js"),
		filepath.Join(root, "x.git"),
		filepath.Join(root, ".gitignore"),
	}

	globs := []string{"**/.git/**", "!**/.git/**", "!**/config", "!**/HEAD"}

	fileFilter := NewFileFilter(root, &log.Logger)
	got := drainFilteredFiles(t, fileFilter.GetFilteredFiles(filesChannel(inputs), globs))

	expected := []string{
		filepath.Join(root, ".github", "x.yml"),
		filepath.Join(root, "a.git", "x.js"),
		filepath.Join(root, "x.git"),
		filepath.Join(root, ".gitignore"),
	}
	assert.ElementsMatch(t, expected, got)

	t.Run("per-input", func(t *testing.T) {
		tests := []struct {
			input string
			kept  bool
		}{
			{filepath.Join(root, ".git", "config"), false},
			{filepath.Join(root, ".git"), false},
			{filepath.Join(root, "sub", ".git"), false},
			{filepath.Join(root, "sub", ".git", "HEAD"), false},
			{filepath.Join(root, ".github", "x.yml"), true},
			{filepath.Join(root, "a.git", "x.js"), true},
			{filepath.Join(root, "x.git"), true},
			{filepath.Join(root, ".gitignore"), true},
		}

		for _, tt := range tests {
			t.Run(tt.input, func(t *testing.T) {
				fileFilter := NewFileFilter(root, &log.Logger)
				got := drainFilteredFiles(t, fileFilter.GetFilteredFiles(filesChannel([]string{tt.input}), globs))
				if tt.kept {
					assert.Len(t, got, 1)
				} else {
					assert.Len(t, got, 0)
				}
			})
		}
	})
}

func TestGetFilteredFiles_NeverReturnsGitFolderFilesWithAllowlistRules(t *testing.T) {
	root := t.TempDir()
	createFileInPath(t, filepath.Join(root, ".gitignore"), []byte("*\n!*/\n!keep.txt\n"))
	createFileInPath(t, filepath.Join(root, "keep.txt"), []byte{})
	createFileInPath(t, filepath.Join(root, ".git", "keep.txt"), []byte{})

	fileFilter := NewFileFilter(root, &log.Logger)
	rules, err := fileFilter.GetRules([]string{".gitignore"})
	require.NoError(t, err)

	inputs := []string{
		filepath.Join(root, "keep.txt"),
		filepath.Join(root, ".git", "keep.txt"),
	}

	got := drainFilteredFiles(t, fileFilter.GetFilteredFiles(filesChannel(inputs), rules))

	expected := []string{filepath.Join(root, "keep.txt")}
	assert.ElementsMatch(t, expected, got)
}
