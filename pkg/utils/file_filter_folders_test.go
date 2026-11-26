package utils

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestFolderExclusions_ParentFolder(t *testing.T) {
	tests := []struct {
		name       string
		root       string
		path       string
		wantFolder string
		wantOK     bool
	}{
		{"dot root, file in folder", ".", "a/b.txt", "a", true},
		{"dot root, file in nested folder", ".", "a/b/c.txt", "a/b", true},
		{"dot root, file directly in root", ".", "a.txt", "", false},
		{"dot root, dot-prefixed folder", ".", "..hidden/b.txt", "..hidden", true},
		{"dot root, path above root", ".", "../a/b.txt", "", false},
		{"dot root, folder above root", ".", "../a", "", false},
		{"dot root, parent folder itself", ".", "..", "", false},
		{"dot root, absolute path", ".", "/a/b.txt", "", false},
		{"unclean dot root, path above root", "a/..", "../a/b.txt", "", false},
		{"unclean dot root, file in folder", "a/..", "x/b.txt", "x", true},
		{"named root, file in folder", "root", "root/a/b.txt", "root/a", true},
		{"named root, file directly in root", "root", "root/b.txt", "", false},
		{"named root, path outside", "root", "other/a/b.txt", "", false},
		{"parent root, file in folder", "..", "../a/b.txt", "../a", true},
		{"absolute root, path outside", "/root", "/other/a/b.txt", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &folderExclusions{rootPrefix: folderRootPrefix(tt.root)}
			folder, ok := e.parentFolder(tt.path)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantFolder, folder)
		})
	}
}

func TestFolderExclusions_ExcludedByFolder_RelativeRoot(t *testing.T) {
	fileFilter := NewFileFilter(".", &log.Logger, WithConfig(newTestConfig(nil)))
	folders := fileFilter.newFolderExclusions([]string{"**/x/**"})

	assert.True(t, folders.excludedByFolder("x/f.txt"))
	assert.False(t, folders.excludedByFolder("../x/f.txt"))
	assert.False(t, folders.excludedByFolder("/x/f.txt"))
}
