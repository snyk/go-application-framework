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
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Codes come from the catalog constructors, so a renumbered entry does not fail the tests.
var (
	codeInvalidName = cli.NewInvalidConfigProfileNameError("").ErrorCode
	codeUnreadable  = cli.NewConfigProfileUnreadableError("").ErrorCode
	codeDirInvalid  = cli.NewConfigProfileDirectoryInvalidError("").ErrorCode
	codeUnavailable = cli.NewConfigProfilesUnavailableError("").ErrorCode
)

// assertCatalogError asserts that err is the catalog error itself, not a wrapper of one, with the code and detail, and
// that it has no upstream cause, because a cause would put its path into the marshaled error.
func assertCatalogError(t *testing.T, err error, code, detail string) {
	t.Helper()
	// IsType fails for a wrapper, which errors.As would still find
	if !assert.IsType(t, snyk_errors.Error{}, err, "the error must not be wrapped") {
		return
	}
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, code, catalogErr.ErrorCode)
	assert.Equal(t, detail, catalogErr.Detail)
	assert.Nil(t, errors.Unwrap(catalogErr), "the error must have no upstream cause")
}

func skipWithoutPermissionBits(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits do not restrict access on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits")
	}
}

// skipOnWindowsRegularFileDir skips a case whose directory is a regular file: Windows reports a path under a regular
// file as missing, so the lookup does not fail there.
func skipOnWindowsRegularFileDir(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("windows reports a path under a regular file as missing")
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
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

func Test_NewFileRegistry_UnusableDirIsDirectoryInvalid(t *testing.T) {
	tests := []struct {
		dir    string
		detail string
	}{
		{dir: "", detail: "The profile directory is not set. Set config_profile_dir to an absolute path."},
		{dir: ".", detail: "The profile directory must be an absolute path. Set config_profile_dir to one."},
		{dir: "relative/dir", detail: "The profile directory must be an absolute path. Set config_profile_dir to one."},
	}
	for _, tc := range tests {
		reg, err := NewFileRegistry(tc.dir, configuration.NewWithOpts())
		assertCatalogError(t, err, codeDirInvalid, tc.detail)
		assert.Nil(t, reg, tc.dir)
	}
}

func Test_Registry_DefaultProfileIsBase(t *testing.T) {
	env := newTestRegistry(t)
	p, err := env.reg.Profile(DefaultName)
	require.NoError(t, err)
	assert.Equal(t, DefaultName, p.Name())
	assert.Same(t, env.base, p.Configuration())
}

func Test_Registry_UnusableProfileDirectoryIsDirectoryInvalid(t *testing.T) {
	tests := []struct {
		name   string
		dir    func(t *testing.T) string
		reason string
	}{
		{
			name: "directory_is_a_regular_file",
			dir: func(t *testing.T) string {
				t.Helper()
				skipOnWindowsRegularFileDir(t)
				dir := filepath.Join(t.TempDir(), "not-a-dir")
				require.NoError(t, os.WriteFile(dir, []byte("{}"), 0o600))
				return dir
			},
			reason: "not a directory",
		},
		{
			name: "parent_directory_without_search_permission",
			dir: func(t *testing.T) string {
				t.Helper()
				skipWithoutPermissionBits(t)
				parent := filepath.Join(t.TempDir(), "locked")
				dir := filepath.Join(parent, "profiles")
				require.NoError(t, os.MkdirAll(dir, 0o700))
				require.NoError(t, os.Chmod(parent, 0o000))
				// registered after t.TempDir, so it runs before the tree is removed
				t.Cleanup(func() { assert.NoError(t, os.Chmod(parent, 0o700)) })
				if _, err := os.Stat(dir); !errors.Is(err, fs.ErrPermission) {
					t.Skip("the permission change has no effect here")
				}
				return dir
			},
			reason: "permission denied",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestRegistryIn(t, tc.dir(t))

			_, err := env.reg.Profile("work")
			assertCatalogError(t, err, codeDirInvalid, "The profile directory cannot be used: "+tc.reason+".")
			assert.NotErrorIs(t, err, fs.ErrNotExist, "the directory exists, so the lookup of its file must not report that it does not")
		})
	}
}

func Test_Registry_NameValidation(t *testing.T) {
	env := newTestRegistry(t)
	for _, name := range []string{"", "Work", "bad name", "../x", "a/b"} {
		_, err := env.reg.Profile(name)
		assertCatalogError(t, err, codeInvalidName, fmt.Sprintf(
			`Profile name %q is invalid: use lowercase letters, digits, "-" or "_".`,
			name,
		))
	}
	for _, name := range []string{"work", "a-b_1"} {
		_, err := env.reg.Profile(name)
		assert.NoError(t, err, name)
	}
}

func Test_Registry_UnusableProfileFileIsUnreadable(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		why   string
	}{
		{
			name: "invalid_json",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				writeProfile(t, dir, "x", "{not json")
			},
			why: "the file is not valid JSON",
		},
		{
			name: "json_null",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				writeProfile(t, dir, "x", "null")
			},
			why: "the file is not a JSON object",
		},
		{
			name: "symbolic_link_to_a_valid_profile",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				symlink(t, writeProfile(t, t.TempDir(), "target", "{}"), filepath.Join(dir, "x.json"))
			},
			why: "it is not a regular file",
		},
		{
			name: "unreadable_file",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				skipWithoutPermissionBits(t)
				require.NoError(t, os.Chmod(writeProfile(t, dir, "x", "{}"), 0))
			},
			why: "permission denied",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestRegistry(t)
			tc.setup(t, env.dir)

			_, err := env.reg.Profile("x")
			assertCatalogError(t, err, codeUnreadable, fmt.Sprintf("Profile %q cannot be read: %s.", "x", tc.why))
		})
	}
}

func Test_Registry_DeriveFailureIsUnavailable(t *testing.T) {
	base := struct{ configuration.Configuration }{configuration.NewWithOpts()}
	reg, err := NewFileRegistry(t.TempDir(), base)
	require.NoError(t, err)

	_, err = reg.Profile("work")
	assertCatalogError(t, err, codeUnavailable, `Profile "work" cannot be loaded.`)
}

// Test_Registry_ErrorsDoNotLeakPaths checks that the marshaled errors of an unreadable file and of an unusable directory
// hold no path, because the OS error that carries the path is not kept as a cause.
func Test_Registry_ErrorsDoNotLeakPaths(t *testing.T) {
	t.Run("unreadable_file", func(t *testing.T) {
		skipWithoutPermissionBits(t)
		env := newTestRegistry(t)
		path := writeProfile(t, env.dir, "x", "{}")
		require.NoError(t, os.Chmod(path, 0))

		_, err := env.reg.Profile("x")
		require.Error(t, err)
		assertNoPath(t, err, env.dir)
	})
	t.Run("directory_is_a_regular_file", func(t *testing.T) {
		skipOnWindowsRegularFileDir(t)
		dir := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(dir, []byte("{}"), 0o600))
		reg, err := NewFileRegistry(dir, configuration.NewWithOpts())
		require.NoError(t, err)

		_, err = reg.Profile("work")
		require.Error(t, err)
		assertNoPath(t, err, dir)
	})
}

// assertNoPath asserts that the JSON of err does not contain the path of the test directory.
func assertNoPath(t *testing.T, err error, path string) {
	t.Helper()
	marshaled, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)
	assert.NotContains(t, string(marshaled), path)
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

func Test_Registry_DirectoryThatIsASymbolicLinkToADirectoryIsUsed(t *testing.T) {
	target := t.TempDir()
	writeProfile(t, target, "work", `{"own": "work"}`)
	link := filepath.Join(t.TempDir(), "link")
	symlink(t, target, link)
	env := newTestRegistryIn(t, link)

	p, err := env.reg.Profile("work")
	require.NoError(t, err)
	assert.Equal(t, "work", p.Configuration().GetString("own"))

	absent, err := env.reg.Profile("absent")
	require.NoError(t, err)
	assert.Empty(t, absent.Configuration().GetString("own"))
}
