package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNotSymlink(t *testing.T) {
	dir := t.TempDir()
	createFileInPath(t, filepath.Join(dir, "real-dir", "file.js"), []byte("x"))
	symlinkOrSkip(t, filepath.Join(dir, "real-dir", "file.js"), filepath.Join(dir, "file-link"))
	symlinkOrSkip(t, "real-dir", filepath.Join(dir, "dir-link"))
	symlinkOrSkip(t, "missing", filepath.Join(dir, "broken-link"))
	sep := string(os.PathSeparator)

	cases := []struct {
		name      string
		path      string
		isSymlink bool
	}{
		{name: "regular file", path: filepath.Join(dir, "real-dir", "file.js")},
		{name: "directory", path: filepath.Join(dir, "real-dir")},
		{name: "directory with trailing separator", path: filepath.Join(dir, "real-dir") + sep},
		{name: "symlinked file", path: filepath.Join(dir, "file-link"), isSymlink: true},
		{name: "symlinked directory", path: filepath.Join(dir, "dir-link"), isSymlink: true},
		{name: "symlink with trailing separator", path: filepath.Join(dir, "dir-link") + sep, isSymlink: true},
		{name: "symlink with repeated trailing separators", path: filepath.Join(dir, "dir-link") + sep + sep, isSymlink: true},
		{name: "symlink with trailing dot element", path: filepath.Join(dir, "dir-link") + sep + ".", isSymlink: true},
		{name: "symlink with trailing dot element and separator", path: filepath.Join(dir, "dir-link") + sep + "." + sep, isSymlink: true},
		{name: "path through symlinked parent", path: filepath.Join(dir, "dir-link", "file.js")},
		{name: "broken symlink", path: filepath.Join(dir, "broken-link"), isSymlink: true},
		{name: "missing path", path: filepath.Join(dir, "missing")},
		{name: "empty path", path: ""},
		{name: "filesystem root", path: filepath.VolumeName(dir) + sep},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckNotSymlink(tc.path)

			if !tc.isSymlink {
				assert.NoError(t, err)
				return
			}
			var symlinkErr *SymlinkError
			require.ErrorAs(t, err, &symlinkErr)
			assert.Equal(t, tc.path, symlinkErr.Path)
			assert.Equal(t, tc.path+" is a symbolic link. Snyk does not follow symbolic links; pass the real path instead.", err.Error())
		})
	}
}
