package configuration

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_JsonStorage_Set_WhenTheNewFileCannotReplaceTheOld(t *testing.T) {
	renameConfigFile = func(string, string) error { return errRefusedRename }
	t.Cleanup(func() { renameConfigFile = os.Rename })

	t.Run("an existing file is written in place", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"existing":"value"}`), 0o600))

		require.NoError(t, NewJsonStorage(path).Set("existing", "new"))

		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, `{"existing":"new"}`, string(contents))
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1, "no temporary file is left behind")
	})

	t.Run("a missing file reports the error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		err := NewJsonStorage(path).Set("existing", "new")

		require.ErrorIs(t, err, errRefusedRename)
		assert.NoFileExists(t, path)
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries, "no temporary file is left behind")
	})
}

func Test_JsonStorage_Set_ReturnsAFullDiskErrorInsteadOfWritingInPlace(t *testing.T) {
	renameConfigFile = func(string, string) error { return syscall.ENOSPC }
	t.Cleanup(func() { renameConfigFile = os.Rename })
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	const existing = `{"existing":"value"}`
	require.NoError(t, os.WriteFile(path, []byte(existing), 0o600))

	err := NewJsonStorage(path).Set("existing", "new")

	require.ErrorIs(t, err, syscall.ENOSPC)
	contents, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, existing, string(contents), "the file is neither truncated nor missing")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left behind")
}

func Test_resolveConfigPath_RefusesALoop(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	require.NoError(t, os.Symlink(a, b))

	_, err := resolveConfigPath(a)

	assert.ErrorIs(t, err, syscall.ELOOP)
}

// symlinkChain builds under the physical directory, which is what resolveConfigPath returns.
func symlinkChain(t *testing.T, dir string, links int) (first, target string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	target = filepath.Join(dir, "target.json")
	next := target
	for i := links; i > 0; i-- {
		link := filepath.Join(dir, "link"+strconv.Itoa(i)+".json")
		if err := os.Symlink(next, link); err != nil {
			t.Skipf("symlinks are not available here: %v", err)
		}
		next = link
	}
	return next, target
}

func Test_resolveConfigPath_FollowsUpToMaxSymlinkHops(t *testing.T) {
	t.Run("a chain of exactly the bound resolves", func(t *testing.T) {
		first, target := symlinkChain(t, t.TempDir(), maxSymlinkHops)

		resolved, err := resolveConfigPath(first)

		require.NoError(t, err)
		assert.Equal(t, target, resolved)
	})

	t.Run("one more link is refused", func(t *testing.T) {
		first, _ := symlinkChain(t, t.TempDir(), maxSymlinkHops+1)

		_, err := resolveConfigPath(first)

		assert.ErrorIs(t, err, syscall.ELOOP)
	})
}
