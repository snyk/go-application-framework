package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// The expected error codes come from the catalog entries themselves, so a renumbering cannot leave the tests behind.
var (
	codeInvalidName = cli.NewInvalidConfigProfileNameError("").ErrorCode
	codeUnreadable  = cli.NewConfigProfileUnreadableError("").ErrorCode
	codeDirInvalid  = cli.NewConfigProfileDirectoryInvalidError("").ErrorCode
	codeUnavailable = cli.NewConfigProfilesUnavailableError("").ErrorCode
)

// assertCatalogError checks that err is an error-catalog error with the code, that its detail names the profile, and
// that it still matches the sentinel, if one is given.
func assertCatalogError(t *testing.T, err error, code string, sentinel error, name string) {
	t.Helper()
	var catalogErr snyk_errors.Error
	if assert.ErrorAs(t, err, &catalogErr, name) {
		assert.Equal(t, code, catalogErr.ErrorCode, name)
		assert.Contains(t, catalogErr.Detail, name)
	}
	if sentinel != nil {
		assert.ErrorIs(t, err, sentinel, name)
	}
}

// registryEnv is a registry under test with the configuration it derives from and the files it works with.
type registryEnv struct {
	reg      Registry
	base     configuration.Configuration
	dir      string
	baseFile string
}

// newTestRegistry returns a registry that reads the profiles from a new temporary directory. The base configuration
// is stored in another temporary directory, whose file is baseFile.
func newTestRegistry(t *testing.T) registryEnv {
	t.Helper()
	return newTestRegistryIn(t, t.TempDir())
}

// newTestRegistryIn returns a registry that reads the profiles from dir, which need not exist yet.
func newTestRegistryIn(t *testing.T, dir string) registryEnv {
	t.Helper()
	baseFile := filepath.Join(t.TempDir(), "snyk.json")
	base := configuration.NewWithOpts(
		configuration.WithPinnedFile(baseFile),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	reg, err := NewFileRegistry(dir, base)
	require.NoError(t, err)
	return registryEnv{reg: reg, base: base, dir: dir, baseFile: baseFile}
}

func writeProfile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// Test_NewFileRegistry_EmptyDirIsNotSet checks that an empty profile directory is the invalid profile directory error,
// and that its detail names the key of the directory.
func Test_NewFileRegistry_EmptyDirIsNotSet(t *testing.T) {
	_, err := NewFileRegistry("", configuration.NewWithOpts())
	var catalogErr snyk_errors.Error
	if assert.ErrorAs(t, err, &catalogErr) {
		assert.Equal(t, codeDirInvalid, catalogErr.ErrorCode)
		assert.Contains(t, catalogErr.Detail, DirKey)
		assert.Contains(t, catalogErr.Detail, "absolute path")
	}
}

// Test_NewFileRegistry_RelativeDirIsAnError checks that a directory which is not absolute is the invalid profile
// directory error, and that its detail names the directory.
func Test_NewFileRegistry_RelativeDirIsAnError(t *testing.T) {
	base := configuration.NewWithOpts()
	for _, dir := range []string{".", "relative/dir"} {
		_, err := NewFileRegistry(dir, base)
		var catalogErr snyk_errors.Error
		if assert.ErrorAs(t, err, &catalogErr, dir) {
			assert.Equal(t, codeDirInvalid, catalogErr.ErrorCode, dir)
			assert.Contains(t, catalogErr.Detail, fmt.Sprintf("%q", dir))
			assert.Contains(t, catalogErr.Detail, "absolute path")
		}
	}
}

// lstatCause returns the operating system error that the lookup of the profile file reports in dir.
func lstatCause(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, "work.json"))
	return errors.Unwrap(err)
}

// Test_Registry_UnusableProfileDirectoryIsDirectoryInvalid checks that a directory that cannot be inspected gives the
// invalid directory error, not ErrCorrupt, with the reason but no path in the detail and the OS error as the cause.
func Test_Registry_UnusableProfileDirectoryIsDirectoryInvalid(t *testing.T) {
	tests := []struct {
		name   string
		dir    func(t *testing.T) string
		reason string
		// cause returns the OS error of the lookup of the profile file in dir
		cause func(dir string) error
	}{
		{
			// on windows, a path under a regular file reports ERROR_PATH_NOT_FOUND, which matches fs.ErrNotExist
			name: "directory_is_a_regular_file",
			dir: func(t *testing.T) string {
				t.Helper()
				dir := filepath.Join(t.TempDir(), "not-a-dir")
				require.NoError(t, os.WriteFile(dir, []byte("{}"), 0o600))
				return dir
			},
			reason: "not a directory",
			cause:  lstatCause,
		},
		{
			// linux fails the lookup with ENOTDIR; windows reports not-exist, so the directory check follows the link
			name: "directory_is_a_symbolic_link_to_a_regular_file",
			dir: func(t *testing.T) string {
				t.Helper()
				target := filepath.Join(t.TempDir(), "target")
				require.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("cannot create symlink: %v", err)
				}
				return link
			},
			reason: "not a directory",
			cause:  lstatCause,
		},
		{
			name: "parent_directory_without_search_permission",
			dir: func(t *testing.T) string {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("file permission bits do not restrict directory lookups on windows")
				}
				if os.Geteuid() == 0 {
					t.Skip("root ignores the permission bits")
				}
				parent := filepath.Join(t.TempDir(), "locked")
				dir := filepath.Join(parent, "profiles")
				require.NoError(t, os.MkdirAll(dir, 0o700))
				require.NoError(t, os.Chmod(parent, 0o000))
				// runs before t.TempDir removes the tree
				t.Cleanup(func() {
					if err := os.Chmod(parent, 0o700); err != nil {
						t.Logf("cannot restore the permissions of %s: %v", parent, err)
					}
				})
				if _, err := os.Stat(dir); !errors.Is(err, fs.ErrPermission) {
					t.Skip("the permission change has no effect here")
				}
				return dir
			},
			reason: "permission denied",
			cause:  func(string) error { return syscall.EACCES },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.dir(t)
			env := newTestRegistryIn(t, dir)

			_, err := env.reg.Profile("work")
			var catalogErr snyk_errors.Error
			if assert.ErrorAs(t, err, &catalogErr) {
				assert.Equal(t, codeDirInvalid, catalogErr.ErrorCode)
				assert.Equal(t, "The profile directory cannot be used: "+tc.reason+".", catalogErr.Detail)
				assert.NotContains(t, catalogErr.Detail, dir)
			}
			assert.NotErrorIs(t, err, ErrCorrupt)
			assert.ErrorIs(t, err, tc.cause(dir))
		})
	}
}

// Test_Registry_ArrayProfileDetailNamesNoGoType checks that a JSON array profile is reported without a Go type name.
func Test_Registry_ArrayProfileDetailNamesNoGoType(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "list", "[1]")

	_, err := env.reg.Profile("list")
	assertCatalogError(t, err, codeUnreadable, ErrCorrupt, "list")
	var catalogErr snyk_errors.Error
	if assert.ErrorAs(t, err, &catalogErr) {
		assert.NotContains(t, catalogErr.Detail, "Go value")
		assert.Contains(t, catalogErr.Detail, "the file does not contain a JSON object")
	}
}

// Test_Registry_UnreadableProfileDetailNamesNoPath checks that the detail names neither the file nor the directory path.
func Test_Registry_UnreadableProfileDetailNamesNoPath(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "broken", "{not json")

	_, err := env.reg.Profile("broken")
	var catalogErr snyk_errors.Error
	if assert.ErrorAs(t, err, &catalogErr) {
		assert.Equal(t, codeUnreadable, catalogErr.ErrorCode)
		assert.Contains(t, catalogErr.Detail, "broken")
		assert.NotContains(t, catalogErr.Detail, filepath.Join(env.dir, "broken.json"))
		assert.NotContains(t, catalogErr.Detail, env.dir)
	}
}

// Test_Registry_ErrorTextIsTheCatalogTitle checks that the text of each profile error is the title of its catalog entry.
func Test_Registry_ErrorTextIsTheCatalogTitle(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "broken", "{not json")

	_, err := env.reg.Profile("Bad Name")
	assert.Equal(t, cli.NewInvalidConfigProfileNameError("").Title, err.Error())

	_, err = env.reg.Profile("broken")
	assert.Equal(t, cli.NewConfigProfileUnreadableError("").Title, err.Error())

	_, err = NewFileRegistry("relative/dir", env.base)
	assert.Equal(t, cli.NewConfigProfileDirectoryInvalidError("").Title, err.Error())
}

// Test_Registry_DeriveFailureIsUnavailable checks that a profile which cannot be derived from the base configuration is
// the profiles unavailable error, whose detail names the profile.
func Test_Registry_DeriveFailureIsUnavailable(t *testing.T) {
	base := struct{ configuration.Configuration }{configuration.NewWithOpts()}
	reg, err := NewFileRegistry(t.TempDir(), base)
	require.NoError(t, err)

	_, err = reg.Profile("work")
	var catalogErr snyk_errors.Error
	if assert.ErrorAs(t, err, &catalogErr) {
		assert.Equal(t, codeUnavailable, catalogErr.ErrorCode)
		assert.Contains(t, catalogErr.Detail, "work")
	}
}

func Test_Registry_DefaultProfileIsBase(t *testing.T) {
	env := newTestRegistry(t)
	p, err := env.reg.Profile(DefaultName)
	require.NoError(t, err)
	assert.Equal(t, DefaultName, p.Name())
	assert.Same(t, env.base, p.Configuration())
}

func Test_Registry_NameValidation(t *testing.T) {
	env := newTestRegistry(t)
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
		{name: strings.Repeat("a", 250), invalid: false},
		{name: strings.Repeat("a", 251), invalid: true},
	}
	for _, tc := range tests {
		_, err := env.reg.Profile(tc.name)
		if tc.invalid {
			assertCatalogError(t, err, codeInvalidName, ErrInvalidName, tc.name)
		} else {
			assert.NoError(t, err, tc.name)
		}
	}
}

// Test_Registry_ProfileReadsOnlyItsOwnFile checks that the profile directory holds the profile files directly, as
// <name>.json, and that a profile reads only its own file.
func Test_Registry_ProfileReadsOnlyItsOwnFile(t *testing.T) {
	env := newTestRegistry(t)
	env.base.Set("only_base", "base")
	writeProfile(t, env.dir, "work", `{"own": "work"}`)

	p, err := env.reg.Profile("work")
	require.NoError(t, err)
	assert.Equal(t, "work", p.Name())
	assert.Equal(t, "work", p.Configuration().GetString("own"))
	assert.Nil(t, p.Configuration().Get("only_base"))
}

func Test_Registry_SetWritesOnlyTheProfileFile(t *testing.T) {
	env := newTestRegistry(t)
	env.base.PersistInStorage("key")
	env.base.Set("key", "base")
	baseBefore, err := os.ReadFile(env.baseFile)
	require.NoError(t, err)

	profileFile := writeProfile(t, env.dir, "work", "{}")
	p, err := env.reg.Profile("work")
	require.NoError(t, err)
	p.Configuration().Set("key", "work")

	profileBytes, err := os.ReadFile(profileFile)
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, json.Unmarshal(profileBytes, &values))
	assert.Equal(t, "work", values["key"])

	baseAfter, err := os.ReadFile(env.baseFile)
	require.NoError(t, err)
	assert.Equal(t, baseBefore, baseAfter)
	assert.Equal(t, "base", env.base.GetString("key"))
}

func Test_Registry_ProfileIsCachedPerName(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "work", "{}")

	first, err := env.reg.Profile("work")
	require.NoError(t, err)
	again, err := env.reg.Profile("work")
	require.NoError(t, err)
	assert.Same(t, first, again)
}

// Test_Registry_MissingProfileIsEmptyAndCreatesNothing checks that a profile without a file is an empty profile, and that
// neither finding it nor reading it creates the profile directory, which does not exist yet, or a file.
func Test_Registry_MissingProfileIsEmptyAndCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-yet")
	env := newTestRegistryIn(t, dir)
	env.base.Set("only_base", "base")

	p, err := env.reg.Profile("new")
	require.NoError(t, err)
	assert.Equal(t, "new", p.Name())
	assert.Nil(t, p.Configuration().Get("only_base"))
	assert.Empty(t, p.Configuration().GetString("own"))

	_, err = os.Stat(dir)
	assert.ErrorIs(t, err, fs.ErrNotExist, "reading must not create the profile directory")
}

// Test_Registry_MissingProfileIsLoggedOncePerName checks that a profile without a file is logged at debug level once
// per name, with the path of the file the profile would be stored in, and that a profile with a file is not logged.
func Test_Registry_MissingProfileIsLoggedOncePerName(t *testing.T) {
	dir := t.TempDir()
	writeProfile(t, dir, "present", `{"own":"value"}`)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	reg, err := NewFileRegistry(dir, configuration.NewWithOpts(), WithLogger(&logger))
	require.NoError(t, err)

	for _, name := range []string{"nonexistent", "nonexistent", "present", "other"} {
		_, err = reg.Profile(name)
		require.NoError(t, err)
	}

	want := []string{
		fmt.Sprintf("profile %q has no file yet, using an empty profile (%s)", "nonexistent", filepath.Join(dir, "nonexistent.json")),
		fmt.Sprintf("profile %q has no file yet, using an empty profile (%s)", "other", filepath.Join(dir, "other.json")),
	}
	assert.Equal(t, want, debugMessagesOf(t, logs.String()))
}

// debugMessagesOf returns the messages of the debug entries in the JSON log output.
func debugMessagesOf(t *testing.T, logOutput string) []string {
	t.Helper()
	var messages []string
	for line := range strings.SplitSeq(strings.TrimSpace(logOutput), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry.Level == zerolog.DebugLevel.String() {
			messages = append(messages, entry.Message)
		}
	}
	return messages
}

// Test_Registry_PersistedWriteCreatesTheProfileFile checks that the first persisted write of a missing profile creates
// the profile directory and the profile file with owner-only permissions, and that the base configuration file is not
// changed.
func Test_Registry_PersistedWriteCreatesTheProfileFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-yet")
	env := newTestRegistryIn(t, dir)
	env.base.PersistInStorage("key")
	env.base.Set("key", "base")
	baseBefore, err := os.ReadFile(env.baseFile)
	require.NoError(t, err)

	p, err := env.reg.Profile("new")
	require.NoError(t, err)
	p.Configuration().Set("key", "work")

	profileFile := filepath.Join(dir, "new.json")
	info, err := os.Stat(profileFile)
	require.NoError(t, err)
	// Windows does not have Unix permission bits: it reports 0666 for every writable file
	if runtime.GOOS != "windows" {
		assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
	}

	profileBytes, err := os.ReadFile(profileFile)
	require.NoError(t, err)
	var values map[string]any
	require.NoError(t, json.Unmarshal(profileBytes, &values))
	assert.Equal(t, "work", values["key"])

	baseAfter, err := os.ReadFile(env.baseFile)
	require.NoError(t, err)
	assert.Equal(t, baseBefore, baseAfter)
}

// Test_Registry_NonRegularProfileEntryIsErrCorrupt checks that a symbolic link or a directory named like a profile is
// refused, and that a symbolic link is never followed to its target.
func Test_Registry_NonRegularProfileEntryIsErrCorrupt(t *testing.T) {
	env := newTestRegistry(t)
	target := filepath.Join(t.TempDir(), "target.json")
	require.NoError(t, os.WriteFile(target, []byte("{}"), 0o600))
	if err := os.Symlink(target, filepath.Join(env.dir, "link.json")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	require.NoError(t, os.Mkdir(filepath.Join(env.dir, "folder.json"), 0o700))

	for _, name := range []string{"link", "folder"} {
		_, err := env.reg.Profile(name)
		assertCatalogError(t, err, codeUnreadable, ErrCorrupt, name)
	}
}

func Test_Registry_CorruptProfileIsErrCorrupt(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "broken", "{not json")
	writeProfile(t, env.dir, "list", "[]")
	writeProfile(t, env.dir, "null", "null")

	for _, name := range []string{"broken", "list", "null"} {
		_, err := env.reg.Profile(name)
		assertCatalogError(t, err, codeUnreadable, ErrCorrupt, name)
	}
}

func Test_Registry_EmptyProfileFileIsValid(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "empty", "")

	_, err := env.reg.Profile("empty")
	assert.NoError(t, err)
}

func Test_Registry_ConcurrentProfileCalls(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "work", "{}")

	const n = 16
	profiles := make([]Profile, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			profiles[i], errs[i] = env.reg.Profile("work")
		}()
	}
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i])
		assert.Same(t, profiles[0], profiles[i])
	}
}

// Test_Registry_DirectoryThatIsASymbolicLinkToADirectoryIsUsed checks that a profile directory may be a link.
func Test_Registry_DirectoryThatIsASymbolicLinkToADirectoryIsUsed(t *testing.T) {
	target := t.TempDir()
	writeProfile(t, target, "work", `{"own": "work"}`)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	env := newTestRegistryIn(t, link)

	p, err := env.reg.Profile("work")
	require.NoError(t, err)
	assert.Equal(t, "work", p.Configuration().GetString("own"))

	// no file: the directory check follows the link
	absent, err := env.reg.Profile("absent")
	require.NoError(t, err)
	assert.Empty(t, absent.Configuration().GetString("own"))
}
