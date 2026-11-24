package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WithPinnedFile_ReadsAndPersistsTheFile(t *testing.T) {
	for _, name := range []string{"profile", "profile.cfg"} {
		t.Run(name, func(t *testing.T) {
			isolateHome(t)
			file := filepath.Join(t.TempDir(), name)
			require.NoError(t, os.WriteFile(file, []byte(`{"a":"fromfile"}`), 0o644))

			c := NewWithOpts(WithPinnedFile(file))
			assert.Equal(t, "fromfile", c.GetString("a"))
			assert.Equal(t, jsonFile, asViper(t, c).getConfigType())

			c.PersistInStorage("b")
			c.Set("b", "stored")
			reread := NewWithOpts(WithPinnedFile(file))
			assert.Equal(t, "stored", reread.GetString("b"))
			assert.Equal(t, "fromfile", reread.GetString("a"))
		})
	}
}

func Test_WithPinnedFile_FirstWriteCreatesDirectoryAndFile(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "new", "dir", "profile")
	c := NewWithOpts(WithPinnedFile(file))
	assert.Empty(t, c.GetString("a"))
	assert.NoFileExists(t, file)

	c.PersistInStorage("a")
	c.Set("a", "x")
	assert.FileExists(t, file)
}

func Test_WithPinnedFile_LockIsNextToTheFile(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "profile")
	c := NewWithOpts(WithPinnedFile(file))

	require.NoError(t, c.GetStorage().Lock(t.Context(), time.Millisecond))
	require.NoError(t, c.GetStorage().Unlock())
	assert.FileExists(t, file+".lock")
}

func Test_WithPinnedFile_DoesNotSearch(t *testing.T) {
	isolateHome(t)
	cwd := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cwd, "profile.json"), []byte(`{"a":"stray"}`), 0o644))
	t.Chdir(cwd)

	c := NewWithOpts(WithPinnedFile(filepath.Join(t.TempDir(), "profile.json")))
	assert.Empty(t, c.GetString("a"))
}

func Test_WithPinnedFile_IgnoresWithFiles(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "profile")
	c := NewWithOpts(WithFiles("relative"), WithPinnedFile(file))

	storage, ok := c.GetStorage().(*JsonStorage)
	require.True(t, ok)
	assert.Equal(t, file, storage.path)
}

func Test_WithPinnedFile_PathIsCleanedBeforeUse(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "profile.json")
	dotted := dir + string(filepath.Separator) + "sub" + string(filepath.Separator) + ".." + string(filepath.Separator) + "profile.json"

	storage, ok := NewWithOpts(WithPinnedFile(dotted)).GetStorage().(*JsonStorage)
	require.True(t, ok)
	assert.Equal(t, file, storage.path)
}

func Test_WithPinnedFile_DotDotAfterSymbolicLinkIsRemovedLexically(t *testing.T) {
	isolateHome(t)
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symbolic links are not available: ", err)
	}

	storage, ok := NewWithOpts(WithPinnedFile(link + string(filepath.Separator) + ".." + string(filepath.Separator) + "x.json")).GetStorage().(*JsonStorage)
	require.True(t, ok)
	assert.Equal(t, filepath.Dir(link)+string(filepath.Separator)+"x.json", storage.path)
}

func Test_WithPinnedFile_EmptyAndBlankFilesPersist(t *testing.T) {
	for name, content := range map[string][]byte{"empty": nil, "blank": []byte(" \n\t\n")} {
		t.Run(name, func(t *testing.T) {
			isolateHome(t)
			file := filepath.Join(t.TempDir(), name)
			require.NoError(t, os.WriteFile(file, content, 0o644))

			c := NewWithOpts(WithPinnedFile(file))
			assert.NotNil(t, c.GetStorage())
			c.PersistInStorage("a")
			c.Set("a", "x")
			assert.Equal(t, "x", NewWithOpts(WithPinnedFile(file)).GetString("a"))
		})
	}
}

func Test_WithPinnedFile_CorruptFileIsNotUsedNorOverwritten(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "garbage")
	require.NoError(t, os.WriteFile(file, []byte("not json"), 0o644))
	logs := captureLog(t)

	var c Configuration
	require.NotPanics(t, func() { c = NewWithOpts(WithPinnedFile(file)) })
	assert.Empty(t, c.GetString("a"))
	assert.Nil(t, c.GetStorage())
	assert.Contains(t, logs.String(), "invalid character")

	c.PersistInStorage("a")
	c.Set("a", "x")
	content, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, "not json", string(content))

	_, err = Derive(NewWithOpts(), WithPinnedFile(file))
	assert.ErrorContains(t, err, "invalid character")
}

func Test_WithPinnedFile_UnreadableFileIsNotUsed(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.WriteFile(file, []byte(`{"a":"fromfile"}`), 0o000))
	t.Cleanup(func() {
		// a read-only file on Windows must be writable again for the temporary directory cleanup
		if err := os.Chmod(file, 0o600); err != nil {
			t.Log(err)
		}
	})
	if _, err := os.ReadFile(file); err == nil {
		t.Skip("file permissions are not enforced for this user")
	}
	logs := captureLog(t)

	c := NewWithOpts(WithPinnedFile(file))
	assert.Empty(t, c.GetString("a"))
	assert.Nil(t, c.GetStorage())
	assert.Contains(t, logs.String(), "permission denied")
}

func Test_WithPinnedFile_InvalidPathsGiveReasons(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "profile")
	cases := map[string]struct{ path, reason string }{
		"NUL byte":           {file + "\x00", "NUL byte"},
		"trailing separator": {file + string(filepath.Separator), "ends with a separator"},
		"existing directory": {dir, "is a directory"},
		"relative name":      {"profile", "not an absolute path"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			logs := captureLog(t)
			var c Configuration
			require.NotPanics(t, func() { c = NewWithOpts(WithPinnedFile(tc.path)) })
			assertInMemoryWritesNothing(t, c, dir)
			assert.Contains(t, logs.String(), tc.reason, "NewWithOpts logs why the file is not used")

			_, err := Derive(NewWithOpts(), WithPinnedFile(tc.path))
			assert.ErrorContains(t, err, tc.reason)
		})
	}
}

func Test_WithPinnedFile_CloneSharesTheStorage(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "profile")
	c := NewWithOpts(WithPinnedFile(file))
	clone := c.Clone()
	assert.Same(t, c.GetStorage(), clone.GetStorage())
	assert.Equal(t, jsonFile, asViper(t, clone).getConfigType())
}

func Test_WithPinnedFile_SetKeepsTheTextOfOtherNumbers(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "profile")
	require.NoError(t, os.WriteFile(file, []byte(`{"id":12345678901234567890,"big":9007199254740993}`), 0o644))

	c := NewWithOpts(WithPinnedFile(file))
	c.PersistInStorage("other")
	c.Set("other", "x")

	content, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Contains(t, string(content), "12345678901234567890")
	assert.Contains(t, string(content), "9007199254740993")
}

func Test_WithPinnedFile_DoesNotKeepWithFiles(t *testing.T) {
	isolateHome(t)
	file := filepath.Join(t.TempDir(), "profile")
	c := NewWithOpts(WithFiles("relative"), WithPinnedFile(file))
	assert.Empty(t, c.GetFiles())
}

func Test_WithPinnedFile_UncheckablePathIsNotRead(t *testing.T) {
	isolateHome(t)
	parent := filepath.Join(t.TempDir(), "parent")
	require.NoError(t, os.WriteFile(parent, []byte("a regular file"), 0o644))
	logs := captureLog(t)

	c := NewWithOpts(WithPinnedFile(filepath.Join(parent, "profile.json")))
	if runtime.GOOS == "windows" {
		// Windows reports a file used as a directory as ERROR_PATH_NOT_FOUND, which Go maps to fs.ErrNotExist. The path then
		// counts as a missing file: nothing is read, the storage is attached, and the first write fails at MkdirAll.
		assert.NotNil(t, c.GetStorage())
		assert.Empty(t, c.GetString("a"))
		assert.NotContains(t, logs.String(), "cannot be checked")
		return
	}
	assert.Nil(t, c.GetStorage())
	assert.Contains(t, logs.String(), "cannot be checked")
}
