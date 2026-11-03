package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func newTestRegistry(t *testing.T) (Registry, configuration.Configuration, string) {
	t.Helper()
	dir := t.TempDir()
	base := configuration.NewWithOpts(
		configuration.WithPinnedFile(filepath.Join(dir, "snyk.json")),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	reg, err := NewFileRegistry(dir, base)
	require.NoError(t, err)
	return reg, base, dir
}

func writeProfile(t *testing.T, dir, name, content string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "profiles"), 0o700))
	path := filepath.Join(dir, "profiles", name+".json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func Test_NewFileRegistry_RelativeBaseDirIsAnError(t *testing.T) {
	base := configuration.NewWithOpts()
	for _, dir := range []string{"", ".", "relative/dir"} {
		_, err := NewFileRegistry(dir, base)
		assert.Error(t, err, dir)
	}
}

func Test_Registry_DefaultProfileIsBase(t *testing.T) {
	reg, base, _ := newTestRegistry(t)
	p, err := reg.Profile(DefaultName)
	require.NoError(t, err)
	assert.Equal(t, DefaultName, p.Name())
	assert.Same(t, base, p.Configuration())
}

func Test_Registry_NameValidation(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	tests := []struct {
		name    string
		invalid bool
	}{
		{name: "work", invalid: false},
		{name: "a-b_1", invalid: false},
		{name: "", invalid: true},
		{name: "Work", invalid: true},
		{name: "../x", invalid: true},
		{name: "a/b", invalid: true},
		{name: "nul", invalid: true},
		{name: "com0", invalid: true},
	}
	for _, tc := range tests {
		_, err := reg.Profile(tc.name)
		if tc.invalid {
			assert.ErrorIs(t, err, ErrInvalidName, tc.name)
		} else {
			assert.ErrorIs(t, err, ErrNotFound, tc.name)
		}
	}
}

func Test_Registry_ProfileReadsOnlyItsOwnFile(t *testing.T) {
	reg, base, dir := newTestRegistry(t)
	base.Set("only_base", "base")
	writeProfile(t, dir, "work", `{"own": "work"}`)

	p, err := reg.Profile("work")
	require.NoError(t, err)
	assert.Equal(t, "work", p.Name())
	assert.Equal(t, "work", p.Configuration().GetString("own"))
	assert.Nil(t, p.Configuration().Get("only_base"))
}

func Test_Registry_SetWritesOnlyTheProfileFile(t *testing.T) {
	reg, base, dir := newTestRegistry(t)
	base.PersistInStorage("key")
	base.Set("key", "base")
	baseFile := filepath.Join(dir, "snyk.json")
	baseBefore, err := os.ReadFile(baseFile)
	require.NoError(t, err)

	profileFile := writeProfile(t, dir, "work", "{}")
	p, err := reg.Profile("work")
	require.NoError(t, err)
	p.Configuration().Set("key", "work")

	profileBytes, err := os.ReadFile(profileFile)
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, json.Unmarshal(profileBytes, &values))
	assert.Equal(t, "work", values["key"])

	baseAfter, err := os.ReadFile(baseFile)
	require.NoError(t, err)
	assert.Equal(t, baseBefore, baseAfter)
	assert.Equal(t, "base", base.GetString("key"))
}

func Test_Registry_ProfileIsCachedPerName(t *testing.T) {
	reg, _, dir := newTestRegistry(t)
	writeProfile(t, dir, "work", "{}")

	first, err := reg.Profile("work")
	require.NoError(t, err)
	again, err := reg.Profile("work")
	require.NoError(t, err)
	assert.Same(t, first, again)
}

func Test_Registry_SymlinkedProfileIsNotFound(t *testing.T) {
	reg, _, dir := newTestRegistry(t)
	target := filepath.Join(t.TempDir(), "target.json")
	require.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "profiles"), 0o700))
	if err := os.Symlink(target, filepath.Join(dir, "profiles", "link.json")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	_, err := reg.Profile("link")
	assert.ErrorIs(t, err, ErrNotFound)
}

func Test_Registry_CorruptProfileIsErrCorrupt(t *testing.T) {
	reg, _, dir := newTestRegistry(t)
	writeProfile(t, dir, "broken", "{not json")
	writeProfile(t, dir, "list", "[]")
	writeProfile(t, dir, "null", "null")

	for _, name := range []string{"broken", "list", "null"} {
		_, err := reg.Profile(name)
		assert.ErrorIs(t, err, ErrCorrupt, name)
	}
}

func Test_Registry_EmptyProfileFileIsValid(t *testing.T) {
	reg, _, dir := newTestRegistry(t)
	writeProfile(t, dir, "empty", "")

	_, err := reg.Profile("empty")
	assert.NoError(t, err)
}

func Test_Registry_ConcurrentProfileCalls(t *testing.T) {
	reg, _, dir := newTestRegistry(t)
	writeProfile(t, dir, "work", "{}")

	const n = 16
	profiles := make([]Profile, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			profiles[i], errs[i] = reg.Profile("work")
		}()
	}
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i])
		assert.Same(t, profiles[0], profiles[i])
	}
}
