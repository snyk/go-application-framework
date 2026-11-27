package configuration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tests in this file pin the behavior of the public file options as released. They must pass unchanged on the
// release and on every change that follows.

func Test_Compat_AbsolutePathIsSearchedAndPersistsToConfigDir(t *testing.T) {
	compatIsolateHome(t)
	file := filepath.Join(t.TempDir(), "profile.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"a":"fromfile"}`), 0o644))
	snykJSON := filepath.Join(determineBasePath(), "snyk.json")

	c := NewWithOpts(WithFiles(file))
	assert.Empty(t, c.GetString("a"), "an absolute path is not read")

	c.PersistInStorage("persisted")
	c.Set("persisted", "x")
	content, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":"fromfile"}`, string(content), "the absolute file is not written")
	assert.FileExists(t, snykJSON)
}

func Test_Compat_MixedAndTwoAbsoluteListsSearch(t *testing.T) {
	compatIsolateHome(t)
	file := filepath.Join(t.TempDir(), "profile.json")
	other := filepath.Join(t.TempDir(), "other.json")
	snykJSON := filepath.Join(determineBasePath(), "snyk.json")

	for name, files := range map[string][]string{
		"absolute with relative": {file, "relative"},
		"relative with absolute": {"relative", file},
		"two absolute paths":     {file, other},
	} {
		t.Run(name, func(t *testing.T) {
			c := NewWithOpts(WithFiles(files...))
			storage, ok := c.GetStorage().(*JsonStorage)
			require.True(t, ok)
			assert.Equal(t, filepath.Clean(snykJSON), filepath.Clean(storage.path))
		})
	}
}

func Test_Compat_OrderOfCallsDoesNotMatter(t *testing.T) {
	compatIsolateHome(t)
	file := filepath.Join(t.TempDir(), "profile.json")
	snykJSON := filepath.Join(determineBasePath(), "snyk.json")

	for _, c := range []Configuration{
		NewWithOpts(WithFiles(file), WithFiles("relative")),
		NewWithOpts(WithFiles("relative"), WithFiles(file)),
	} {
		storage, ok := c.GetStorage().(*JsonStorage)
		require.True(t, ok)
		assert.Equal(t, filepath.Clean(snykJSON), filepath.Clean(storage.path))
	}
}

func Test_Compat_RelativeNameReadsConfigDirAndPersists(t *testing.T) {
	compatIsolateHome(t)
	dir := determineBasePath()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "compatname.json"), []byte(`{"a":"fromconfigdir"}`), 0o644))
	t.Chdir(t.TempDir())

	c := NewWithOpts(WithFiles("compatname"))
	assert.Equal(t, "fromconfigdir", c.GetString("a"))
	c.PersistInStorage("b")
	c.Set("b", "stored")
	assert.FileExists(t, filepath.Join(dir, "snyk.json"))
}

func Test_Compat_CorruptAbsoluteFileGivesNoPanic(t *testing.T) {
	compatIsolateHome(t)
	file := filepath.Join(t.TempDir(), "garbage")
	require.NoError(t, os.WriteFile(file, []byte("not json"), 0o644))

	var c Configuration
	require.NotPanics(t, func() { c = NewWithOpts(WithFiles(file)) })
	assert.Empty(t, c.GetString("a"))
}

func Test_Compat_CloneOfRelativeNameKeepsValuesAndFiles(t *testing.T) {
	compatIsolateHome(t)
	require.NoError(t, os.MkdirAll(determineBasePath(), 0o755))
	name := "compatreload"
	file := filepath.Join(determineBasePath(), name+".json")
	require.NoError(t, os.WriteFile(file, []byte(`{"a":"first"}`), 0o644))
	t.Chdir(t.TempDir())

	c := NewWithOpts(WithFiles(name))
	require.NoError(t, os.WriteFile(file, []byte(`{"a":"second","added":"later"}`), 0o644))

	clone := c.Clone()
	assert.Equal(t, "first", clone.GetString("a"), "the clone has the values of the source")
	assert.Empty(t, clone.GetString("added"), "a later change of the file is not seen")
	// ConfigFileUsed uses a slash before the file name on Windows, so the path is compared cleaned
	files := clone.GetFiles()
	require.Len(t, files, 2)
	assert.Equal(t, filepath.Clean(file), filepath.Clean(files[0]), "the clone lists the configuration file it used")
	assert.Equal(t, name, files[1], "then the name")
	assert.Same(t, c.GetStorage(), clone.GetStorage())
	assert.Error(t, clone.ReloadConfig(), "ReloadConfig on a clone fails as released")
}

func Test_Compat_CloneDoesNotPersistPersistedKeys(t *testing.T) {
	compatIsolateHome(t)
	c := NewWithOpts(WithFiles(filepath.Join(t.TempDir(), "profile.json")))
	c.AddAlternativeKeys("compat_main", []string{"compat_alt"})
	c.PersistInStorage("compat_persisted")

	clone := c.Clone()
	assert.Equal(t, []string{"compat_alt"}, clone.GetAlternativeKeys("compat_main"))
	clone.Set("compat_persisted", "fromclone")
	assert.Empty(t, NewWithOpts(WithFiles(filepath.Join(t.TempDir(), "other.json"))).GetString("compat_persisted"))
	assert.Equal(t, "fromclone", clone.GetString("compat_persisted"))
}

func Test_Compat_CloneKeepsInMemoryAndCache(t *testing.T) {
	c := NewWithOpts(WithCachingEnabled(time.Hour))
	c.AddDefaultValue("compat_default", StandardDefaultValueFunction("dflt"))
	clone := c.Clone()
	assert.Equal(t, "dflt", clone.GetString("compat_default"))
	assert.Equal(t, time.Hour, clone.GetDuration(CONFIG_CACHE_TTL))
	assert.Nil(t, clone.GetStorage())
}

func Test_Compat_BlankSnykFileStillFailsPersistedWrite(t *testing.T) {
	file := filepath.Join(t.TempDir(), "blank.json")
	require.NoError(t, os.WriteFile(file, []byte(" \n"), 0o644))
	storage := NewJsonStorage(file)
	assert.Error(t, storage.Set("a", "x"))
}

// compatIsolateHome points the home directory of the test at an empty temporary directory.
func compatIsolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func Test_Compat_MixedListReadsTheConfigDirFile(t *testing.T) {
	compatIsolateHome(t)
	dir := determineBasePath()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snyk.json"), []byte(`{"m":"fromsnyk"}`), 0o644))
	file := filepath.Join(t.TempDir(), "profile.json")

	c := NewWithOpts(WithFiles(file, "snyk"))
	assert.Equal(t, "fromsnyk", c.GetString("m"))
	assert.NotNil(t, c.GetStorage())
}
