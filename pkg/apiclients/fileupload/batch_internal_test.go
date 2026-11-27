package fileupload

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_createUploadFile_ReadAfterBatching(t *testing.T) {
	setup := func(t *testing.T) (dir, path string, reader io.Reader) {
		t.Helper()
		dir = t.TempDir()
		path = filepath.Join(dir, "a.txt")
		require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))

		file, skipped := createUploadFile(dir, path, identity, nil)
		require.Nil(t, skipped)
		return dir, path, file.Reader
	}

	t.Run("a symlink swapped in after batching is not followed", func(t *testing.T) {
		dir, path, reader := setup(t)
		secret := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(secret, []byte("secret"), 0o600))
		require.NoError(t, os.Remove(path))
		if err := os.Symlink(secret, path); err != nil {
			if errors.Is(err, syscall.Errno(1314)) { // ERROR_PRIVILEGE_NOT_HELD on Windows
				t.Skip("creating symlinks on Windows needs Developer Mode or administrator rights")
			}
			require.NoError(t, err)
		}

		content, err := io.ReadAll(reader)

		var symlinkErr *SymlinkError
		require.ErrorAs(t, err, &symlinkErr)
		assert.Equal(t, "a.txt", symlinkErr.FilePath)
		assert.Empty(t, content)
	})

	t.Run("a file replaced by an atomic rename is read", func(t *testing.T) {
		dir, path, reader := setup(t)
		replacement := filepath.Join(dir, "a.txt.tmp")
		require.NoError(t, os.WriteFile(replacement, []byte("saved"), 0o600))
		require.NoError(t, os.Rename(replacement, path))

		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, "saved", string(content))
	})
}
