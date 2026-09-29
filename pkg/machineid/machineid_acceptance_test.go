package machineid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

// newIsolatedConfig builds a real, file-backed Configuration rooted at a fresh temp HOME, and
// points the shared machine-id file and legacy device-id file candidates at temp directories no
// other test can see and that start out empty.
func newIsolatedConfig(t *testing.T) configuration.Configuration {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	machineWideDir := filepath.Join(t.TempDir(), "machine-wide", "snyk")
	perUserDir := filepath.Join(t.TempDir(), "per-user", "snyk")
	sharedFilePaths = func() pathPair {
		return pathPair{
			machineWide: filepath.Join(machineWideDir, "machine-id.json"),
			perUser:     filepath.Join(perUserDir, "machine-id.json"),
		}
	}
	t.Cleanup(func() { sharedFilePaths = defaultSharedFilePaths })

	legacyMachineWideDir := filepath.Join(t.TempDir(), "legacy-machine-wide")
	legacyPerUserDir := filepath.Join(t.TempDir(), "legacy-per-user")
	legacyDeviceIDPaths = func() pathPair {
		return pathPair{
			machineWide: filepath.Join(legacyMachineWideDir, "device-id"),
			perUser:     filepath.Join(legacyPerUserDir, "device-id"),
		}
	}
	t.Cleanup(func() { legacyDeviceIDPaths = defaultLegacyDeviceIDPaths })

	// The Storage this configuration ends up with locks a file inside this directory; like real
	// CLI installs that have already written something under it, the directory needs to exist
	// before the first Lock, since Lock (unlike Set) does not create it.
	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)

	return configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
}

func readSnykJSON(t *testing.T) map[string]any {
	t.Helper()
	home := os.Getenv("HOME")
	data, err := os.ReadFile(filepath.Join(home, ".config", "configstore", "snyk.json"))
	if os.IsNotExist(err) {
		return map[string]any{}
	}
	require.NoError(t, err)
	if len(data) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	return m
}

func TestAcceptance_ExistingStoredValueIsReturnedUnchanged(t *testing.T) {
	config := newIsolatedConfig(t)
	config.Set(configuration.MACHINE_ID, "stored-value-1")
	config.Set(configuration.MACHINE_ID_SOURCE, string(sourceGenerated))
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "stored-value-1", value)
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
}

func TestAcceptance_ValueFoundInSharedFileIsAdopted(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := sharedFile{MachineID: "from-shared-file", IdentifierSource: string(sourceProvided)}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "from-shared-file", value)
	require.Equal(t, string(sourcePersisted), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, "from-shared-file", readSnykJSON(t)[configuration.MACHINE_ID])
}

// TestAcceptance_SharedFileIdentifierSourceIsIgnored proves the shared file's own identifier_source
// field never becomes the resolved source: it is untrusted cross-process input that any Snyk
// product on the machine, or a tampered file, could have written. A value read from the shared file
// is always reported as sourcePersisted regardless of what identifier_source says.
func TestAcceptance_SharedFileIdentifierSourceIsIgnored(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := sharedFile{MachineID: "from-shared-file", IdentifierSource: "whatever-a-tampered-or-buggy-writer-put-here"}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "from-shared-file", value)
	require.Equal(t, string(sourcePersisted), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAcceptance_MachineWideFileWithNoMachineIDDoesNotShadowPerUserFile proves readSharedFile keeps
// scanning candidates rather than stopping at the first one that merely parses: a machine-wide file
// written by other tooling (per the sharedFile doc comment, serial_number/hostname only, no
// machine_id) must not shadow a per-user file that actually holds the shared id.
func TestAcceptance_MachineWideFileWithNoMachineIDDoesNotShadowPerUserFile(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()

	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	machineWideSF := sharedFile{SerialNumber: "5CG1234ABC", Hostname: "some-host"}
	data, err := json.Marshal(machineWideSF)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.machineWide, data, 0o644))

	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	perUserSF := sharedFile{MachineID: "from-per-user-file", IdentifierSource: string(sourceProvided)}
	data, err = json.Marshal(perUserSF)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "from-per-user-file", value, "the per-user file's real machine id must not be orphaned by a machine-wide file that merely parses")
}

// raceWinnerStorage wraps a real Storage and simulates a concurrent writer that already stored an
// id and source by the time this process's Lock succeeds: Refresh populates the caller's scratch
// Configuration with winnerID/winnerSource instead of reading the real backing file.
type raceWinnerStorage struct {
	configuration.Storage
	winnerID     string
	winnerSource string
}

func (s *raceWinnerStorage) Refresh(config configuration.Configuration, key string) error {
	switch key {
	case configuration.MACHINE_ID:
		config.Set(key, s.winnerID)
	case configuration.MACHINE_ID_SOURCE:
		config.Set(key, s.winnerSource)
	}
	return nil
}

// TestAcceptance_ConcurrentWriterWithUnknownSourceInStorageFallsBackToUnknown proves
// mirrorIntoStorage validates the source read back from a concurrent writer's storage entry: unlike
// the shared file, whose identifier_source is never trusted at all, storage's MACHINE_ID_SOURCE is
// only ever written by this package, so an unrecognized value there means an older or newer version
// of it, or a tampered file, wrote it.
func TestAcceptance_ConcurrentWriterWithUnknownSourceInStorageFallsBackToUnknown(t *testing.T) {
	config := newIsolatedConfig(t)
	config.SetStorage(&raceWinnerStorage{
		Storage:      config.GetStorage(),
		winnerID:     "race-winner-id",
		winnerSource: "whatever-a-tampered-or-buggy-writer-put-here",
	})
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "race-winner-id", value)
	require.Equal(t, string(sourceUnknown), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAdoptOrWriteSharedFileReportsWhenAConcurrentWriterWon proves adoptOrWriteSharedFile adopts
// whatever a concurrent writer already put in the shared file, regardless of that writer's own
// identifier_source, and reports that it did so rather than having written the caller's candidate.
func TestAdoptOrWriteSharedFileReportsWhenAConcurrentWriterWon(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine-id.json")
	sf := sharedFile{MachineID: "race-winner-id", IdentifierSource: "whatever-a-tampered-or-buggy-writer-put-here"}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))

	id, wonByOther, err := adoptOrWriteSharedFile(path, false, "candidate-id", sourceGenerated, "test", false, nil)
	require.NoError(t, err)
	require.Equal(t, "race-winner-id", id)
	require.True(t, wonByOther)
}

func TestAcceptance_ExternalChannelIsAdoptedAndPersisted(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "device-managed-id", value)
	require.Equal(t, string(sourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, "device-managed-id", readSnykJSON(t)[configuration.MACHINE_ID])

	sf := readSharedFile(sharedFilePaths(), nil)
	require.NotNil(t, sf)
	require.Equal(t, "device-managed-id", sf.MachineID)
}

// TestAcceptance_ExternalChannelTakesPrecedenceOverSharedFile proves an explicitly supplied value
// wins even when the shared file already holds a different one: the external channel is consulted
// before the shared file.
func TestAcceptance_ExternalChannelTakesPrecedenceOverSharedFile(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := sharedFile{MachineID: "from-shared-file", IdentifierSource: string(sourcePersisted)}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "device-managed-id", value)
	require.Equal(t, string(sourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAcceptance_LegacyFileIsMigratedVerbatim proves a legacy bare-string device-id file left
// behind by an older product installation is adopted as-is (only trailing whitespace trimmed) and
// migrated into the shared file, so every product on the machine converges on it going forward.
func TestAcceptance_LegacyFileIsMigratedVerbatim(t *testing.T) {
	config := newIsolatedConfig(t)
	legacyPaths := legacyDeviceIDPaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPaths.perUser), 0o755))
	require.NoError(t, os.WriteFile(legacyPaths.perUser, []byte("legacy-raw-value\n"), 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "legacy-raw-value", value, "the legacy file's trailing newline is a file-format artifact, not part of the identifier")
	require.Equal(t, string(sourcePersisted), config.GetString(configuration.MACHINE_ID_SOURCE))

	sf := readSharedFile(sharedFilePaths(), nil)
	require.NotNil(t, sf, "a migrated legacy value must be written into the shared file for other products to pick up")
	require.Equal(t, "legacy-raw-value", sf.MachineID)
}

// TestAcceptance_LegacyFileWithLeadingWhitespaceAndControlCharactersFailsValidationAndFallsThrough
// proves a legacy file candidate that fails validation after trailing-whitespace trimming is
// skipped, not adopted with its interior garbage intact.
func TestAcceptance_LegacyFileWithLeadingWhitespaceAndControlCharactersFailsValidationAndFallsThrough(t *testing.T) {
	config := newIsolatedConfig(t)
	legacyPaths := legacyDeviceIDPaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPaths.perUser), 0o755))
	raw := " \t{ABC-99}\x00WEIRD-interior\n\n"
	require.NoError(t, os.WriteFile(legacyPaths.perUser, []byte(raw), 0o644))

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLogger(&logger)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Contains(t, logs.String(), jsonEscapedPath(t, legacyPaths.perUser), "the rejected legacy candidate must be logged together with its path")
}

// TestAcceptance_ExternalChannelValueWithTrailingWhitespaceFailsValidationAndFallsThrough proves the
// external channel is validated like every other candidate: a value is adopted opaquely only once it
// has passed the sanity check, never before.
func TestAcceptance_ExternalChannelValueWithTrailingWhitespaceFailsValidationAndFallsThrough(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id\n")

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLogger(&logger)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.NotEqual(t, "device-managed-id\n", value)
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Contains(t, logs.String(), "external channel value failed validation")
}

// TestAcceptance_SharedFileValueWithTrailingWhitespaceFailsValidationAndFallsThrough proves a
// shared-file candidate is validated the same way: a value with a trailing newline is rejected
// rather than adopted verbatim.
func TestAcceptance_SharedFileValueWithTrailingWhitespaceFailsValidationAndFallsThrough(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := sharedFile{MachineID: "from-shared-file\n", IdentifierSource: string(sourcePersisted)}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.NotEqual(t, "from-shared-file\n", value)
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAcceptance_ExternalChannelValueWithBracesFailsValidationAndFallsThrough proves a brace-wrapped
// GUID, a format some device-management tools historically emit, fails the allowed character set
// and is rejected rather than stored with its braces intact.
func TestAcceptance_ExternalChannelValueWithBracesFailsValidationAndFallsThrough(t *testing.T) {
	config := newIsolatedConfig(t)
	braceWrapped := "{550E8400-E29B-41D4-A716-446655440000}"
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", braceWrapped)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.NotEqual(t, braceWrapped, value)
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAcceptance_WhitespaceOnlyExternalValueFallsThroughToNextSource proves a whitespace-only
// external value is treated as "nothing supplied", not as a blank identifier to reject and log.
func TestAcceptance_WhitespaceOnlyExternalValueFallsThroughToNextSource(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "   ")
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
}

func TestAcceptance_GeneratesUUIDWhenNoOtherSourceApplies(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAcceptance_EphemeralWhenPersistenceFailsEverywhere proves a freshly generated value that
// cannot be written to either the shared file or configuration storage is still returned, but
// recorded as sourceEphemeral rather than sourceGenerated: it will not survive to the next run, so
// anything counting distinct machines by source must not treat it as a stable identity.
func TestAcceptance_EphemeralWhenPersistenceFailsEverywhere(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on windows")
	}
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	require.NoError(t, os.Chmod(filepath.Dir(paths.perUser), 0o555))
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(paths.perUser), 0o755) }) //nolint:errcheck // best-effort cleanup so t.TempDir removal can still recurse into the directory

	config.SetStorage(&lockFailingStorage{Storage: config.GetStorage()})
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))
	require.Equal(t, string(sourceEphemeral), config.GetString(configuration.MACHINE_ID_SOURCE))
}

func TestAcceptance_MachineWideDirUnwritableFallsBackToPerUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on windows")
	}
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	require.NoError(t, os.Chmod(filepath.Dir(paths.machineWide), 0o555))
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(paths.machineWide), 0o755) }) //nolint:errcheck // best-effort cleanup so t.TempDir removal can still recurse into the directory

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	_, machineWideErr := os.Stat(paths.machineWide)
	require.True(t, os.IsNotExist(machineWideErr), "machine-wide file must not be created when its directory is unwritable")
	require.FileExists(t, paths.perUser)
}

// TestAcceptance_MachineWideWriteFailureFallsBackToPerUser covers the fallback selectWritePath's
// own writability probe cannot catch: the probe only checks the directory, so a failure inside
// writeSharedFileValue itself (the lock, the temp file, or the final rename) must still fall back
// to the per-user file rather than silently giving up on persisting the shared value anywhere.
func TestAcceptance_MachineWideWriteFailureFallsBackToPerUser(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	// Pre-create the destination as a directory: the directory-level checks in selectWritePath
	// still pass, but writeSharedFileValue's final os.Rename onto it fails.
	require.NoError(t, os.Mkdir(paths.machineWide, 0o755))

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLogger(&logger)))
	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))

	require.FileExists(t, paths.perUser, "a write-level failure on the machine-wide path must still fall back to the per-user file")
	require.Contains(t, logs.String(), jsonEscapedPath(t, paths.machineWide), "the swallowed machine-wide shared file write failure must be logged together with its path")
}

// TestAcceptance_PerUserSharedFileIsNotGroupOrWorldReadable proves the per-user shared file is
// written owner-only: unlike the machine-wide file, which every product on the machine must be able
// to read, the per-user file lives under the user's home directory and other local users should not
// be able to read this user's machine identifier from it.
func TestAcceptance_PerUserSharedFileIsNotGroupOrWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on windows")
	}
	defer withZeroUmask(t)()

	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	paths := sharedFilePaths()
	info, err := os.Stat(paths.perUser)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// TestAcceptance_MachineWideSharedFileIsWorldReadableButNotWorldWritable proves the machine-wide
// shared file, once its directory is writable by this process (as it would be right after a
// privileged installer created it), is written with owner-write, group/other-read-only
// permissions and takes precedence over any per-user file.
func TestAcceptance_MachineWideSharedFileIsWorldReadableButNotWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on windows")
	}
	defer withZeroUmask(t)()

	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	info, err := os.Stat(paths.machineWide)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	require.NoFileExists(t, paths.perUser, "the machine-wide file must win precedence over the per-user file")
}

// TestAcceptance_DirWritableConcurrentCallsDoNotRace proves dirWritable's probe file name is
// unique per call: naming it after the PID alone is not unique within a process, so concurrent
// resolutions race each other on O_EXCL and on the following os.Remove, and a writable directory
// gets reported unwritable, sending some resolutions to the machine-wide shared file and others to
// the per-user one.
func TestAcceptance_DirWritableConcurrentCallsDoNotRace(t *testing.T) {
	dir := t.TempDir()
	const goroutines = 32
	results := make([]bool, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = dirWritable(dir)
		}(i)
	}
	wg.Wait()

	for i, ok := range results {
		require.True(t, ok, "call %d: a writable directory must be reported writable even under concurrent calls from the same process", i)
	}
}

func TestAcceptance_ConcurrentResolutionsConvergeOnOneValue(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	const goroutines = 8
	results := make([]string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			clone := config.Clone()
			value, err := clone.GetWithError(configuration.MACHINE_ID)
			if !assert.NoError(t, err) {
				return
			}
			id, ok := value.(string)
			assert.True(t, ok)
			results[i] = id
		}(i)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		require.Equal(t, results[0], results[i], "all goroutines must converge on the same machine id")
	}
	require.Equal(t, results[0], readSnykJSON(t)[configuration.MACHINE_ID])
}

func TestAcceptance_ResetClearsStoredValueAndSharedFile(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	first, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	require.NoError(t, reset(config))

	require.Empty(t, readSnykJSON(t)[configuration.MACHINE_ID])
	sf := readSharedFile(sharedFilePaths(), nil)
	if sf != nil {
		require.Empty(t, sf.MachineID)
	}

	second, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "a resolution after reset must not reuse the discarded value")
}

// TestAcceptance_ResetLogsSharedFileLockTimeout proves a logger passed to reset via WithLogger
// reaches the shared file removal reset performs, not just the resolution Resolve wires it into.
func TestAcceptance_ResetLogsSharedFileLockTimeout(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	writePath := selectWritePath(sharedFilePaths(), nil)
	held := flock.New(writePath + ".lock")
	locked, lockErr := held.TryLock()
	require.NoError(t, lockErr)
	require.True(t, locked)
	defer func() { _ = held.Unlock() }() //nolint:errcheck // best-effort cleanup of the test's own lock

	original := lockTimeout
	lockTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lockTimeout = original })

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	err = reset(config, WithLogger(&logger))
	require.Error(t, err, "reset must surface a shared file lock that can never be acquired")
	require.Contains(t, logs.String(), "lock", "a logger passed to reset must reach the shared file removal it performs")
}

// lockFailingStorage wraps a real Storage and fails every Lock call, so a test can simulate a
// storage lock failure independently of any shared-file failure.
type lockFailingStorage struct {
	configuration.Storage
}

func (s *lockFailingStorage) Lock(_ context.Context, _ time.Duration) error {
	return errors.New("simulated lock failure")
}

// multiUnwrapper is the interface errors.Join's result implements; asserting to it lets a test
// check that an error actually joins multiple causes, rather than just checking a string.
type multiUnwrapper interface {
	Unwrap() []error
}

// TestAcceptance_ResetJoinsErrorsFromBothSharedFileCandidates proves a removal failure on one
// shared-file candidate is not discarded when the other also fails: reset must join both errors,
// not let the second overwrite the first.
//
// This no longer pairs a shared-file failure with a storage-lock failure (see
// TestAcceptance_ResetSurfacesStorageLockErrorWhenSharedFileClearSucceeds): reset now leaves
// storage untouched whenever a shared-file candidate cannot be cleared (see
// TestAcceptance_ResetLeavesStorageUntouchedWhenMachineWideFileCannotBeCleared), so storage.Lock
// is never reached once a shared-file removal has already failed.
func TestAcceptance_ResetJoinsErrorsFromBothSharedFileCandidates(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	paths := sharedFilePaths()
	// Replace both shared-file candidates with directories so removeSharedFileValue's rename step
	// cannot complete for either, forcing two independent, deterministic removal failures. Which
	// candidate Resolve actually wrote to is platform-dependent (see selectWritePath), so both are
	// prepared the same way regardless of which one already exists.
	for _, p := range []string{paths.perUser, paths.machineWide} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		if _, statErr := os.Stat(p); statErr == nil {
			require.NoError(t, os.Remove(p))
		}
		require.NoError(t, os.Mkdir(p, 0o755))
	}

	err = reset(config)
	require.Error(t, err)
	mu, ok := err.(multiUnwrapper)
	require.True(t, ok, "reset's error must join both shared-file removal failures, not discard one")
	require.Len(t, mu.Unwrap(), 2)
}

// TestAcceptance_ResetSurfacesStorageLockErrorWhenSharedFileClearSucceeds proves storage.Lock
// failures are still surfaced when they are the only failure: with the shared file clearing
// successfully, reset must still report a storage-lock failure rather than swallowing it.
func TestAcceptance_ResetSurfacesStorageLockErrorWhenSharedFileClearSucceeds(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	config.SetStorage(&lockFailingStorage{Storage: config.GetStorage()})

	err = reset(config)
	require.Error(t, err)
}

// blockingLockStorage wraps a real Storage and blocks on Lock until the caller's context is done,
// simulating a lock holder that never releases (a crashed process, for example).
type blockingLockStorage struct {
	configuration.Storage
}

func (s *blockingLockStorage) Lock(ctx context.Context, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestAcceptance_ResolveDoesNotBlockForeverWhenStorageLockNeverSucceeds proves storage.Lock is
// called with a bounded context: a lock holder that never releases must not be able to hang
// resolution forever.
func TestAcceptance_ResolveDoesNotBlockForeverWhenStorageLockNeverSucceeds(t *testing.T) {
	config := newIsolatedConfig(t)
	config.SetStorage(&blockingLockStorage{Storage: config.GetStorage()})

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLogger(&logger)))

	original := lockTimeout
	lockTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lockTimeout = original })

	done := make(chan error, 1)
	go func() {
		_, err := config.GetWithError(configuration.MACHINE_ID)
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "resolution must still succeed in-memory even when storage.Lock times out")
	case <-time.After(2 * time.Second):
		t.Fatal("resolution did not return: storage.Lock must be bounded by lockTimeout, not block forever on context.Background()")
	}

	require.Contains(t, logs.String(), "storage lock timed out", "the swallowed storage lock timeout must be logged")
}

// TestAcceptance_ResetDoesNotBlockForeverWhenStorageLockNeverSucceeds proves reset's storage.Lock
// call is bounded the same way as resolution's.
func TestAcceptance_ResetDoesNotBlockForeverWhenStorageLockNeverSucceeds(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	config.SetStorage(&blockingLockStorage{Storage: config.GetStorage()})

	original := lockTimeout
	lockTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lockTimeout = original })

	done := make(chan error, 1)
	go func() {
		done <- reset(config)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "reset must surface the timed-out storage lock as an error")
	case <-time.After(2 * time.Second):
		t.Fatal("reset did not return: storage.Lock must be bounded by lockTimeout, not block forever on context.Background()")
	}
}

// resetOrderStorage wraps a real Storage and, for every Set call, records the key and whether the
// shared file (at perUserPath) was already cleared at that moment. This proves reset's actual
// operation order, not just its end state: a concurrent resolve() between reset's two steps must
// only ever be able to observe storage already-cleared-but-file-not-yet-cleared, never the reverse.
type resetOrderStorage struct {
	configuration.Storage
	perUserPath          string
	calls                []string
	fileClearedAtCallFor map[string]bool
}

func (s *resetOrderStorage) Set(key string, value any) error {
	s.calls = append(s.calls, key)
	sf := readSharedFile(pathPair{perUser: s.perUserPath}, nil)
	s.fileClearedAtCallFor[key] = sf == nil || blank(sf.MachineID)
	return s.Storage.Set(key, value)
}

// TestAcceptance_ResetClearsSharedFileBeforeStorageAndDeletesMachineIDBeforeSource proves reset's
// two ordering fixes: the shared file is cleared before storage (so a resolve() racing between the
// two steps still sees the old, correct value in storage rather than re-deriving and re-persisting
// it after reset finishes), and within storage, MACHINE_ID is deleted before MACHINE_ID_SOURCE (the
// mirror image of mirrorIntoStorage's write order, since MACHINE_ID's absence is what a future
// resolve() treats as "not yet resolved").
func TestAcceptance_ResetClearsSharedFileBeforeStorageAndDeletesMachineIDBeforeSource(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	paths := sharedFilePaths()
	writePath := selectWritePath(paths, nil)
	require.FileExists(t, writePath)

	recording := &resetOrderStorage{
		Storage:              config.GetStorage(),
		perUserPath:          writePath,
		fileClearedAtCallFor: map[string]bool{},
	}
	config.SetStorage(recording)

	require.NoError(t, reset(config))

	require.Equal(t, []string{configuration.MACHINE_ID, configuration.MACHINE_ID_SOURCE}, recording.calls,
		"MACHINE_ID must be deleted from storage before MACHINE_ID_SOURCE")
	require.True(t, recording.fileClearedAtCallFor[configuration.MACHINE_ID],
		"the shared file must already be cleared before storage is touched at all")
	require.True(t, recording.fileClearedAtCallFor[configuration.MACHINE_ID_SOURCE],
		"the shared file must already be cleared before storage is touched at all")
}

// TestAcceptance_ResetLeavesStorageUntouchedWhenMachineWideFileCannotBeCleared proves the decision
// documented on reset: when a shared-file candidate cannot be cleared, reset must not clear storage
// either. readSharedFile checks the machine-wide candidate first, so a stale, still-readable value
// left there by a failed clear would win over anything reset does to storage on the very next
// resolution; clearing storage anyway would look like reset succeeded while the effective machine id
// never actually changes, and would additionally throw away the still-valid stored value for no
// benefit.
func TestAcceptance_ResetLeavesStorageUntouchedWhenMachineWideFileCannotBeCleared(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on windows")
	}
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()

	dir := filepath.Dir(paths.machineWide)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, writeSharedFileValue(paths.machineWide, false, "test", func(sf *sharedFile) {
		sf.MachineID = "original-id"
		sf.IdentifierSource = string(sourcePersisted)
	}, nil))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "original-id", readSnykJSON(t)[configuration.MACHINE_ID])

	// Removing write permission on the directory blocks removeSharedFileValue's temp-file step
	// (os.CreateTemp) before it ever touches the existing file, so the file on disk stays exactly as
	// written above: a real, deterministic removal failure with the stale value still fully readable
	// afterward, rather than the file becoming unreadable (which readSharedFile would just skip).
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) //nolint:errcheck // best-effort restore so t.TempDir's cleanup can remove dir

	err = reset(config)
	require.Error(t, err)

	require.Equal(t, "original-id", readSnykJSON(t)[configuration.MACHINE_ID],
		"reset must leave storage untouched when it cannot clear a shared-file candidate that still holds a value")
}

// keyFailingStorage wraps a real Storage and fails every Set call for one key, so a test can
// simulate a crash or I/O error between the two mirrorIntoStorage writes without mocking away the
// Refresh-based recheck path.
type keyFailingStorage struct {
	configuration.Storage
	failKey string
}

func (s *keyFailingStorage) Set(key string, value any) error {
	if key == s.failKey {
		return errors.New("simulated storage failure")
	}
	return s.Storage.Set(key, value)
}

// TestAcceptance_SourceSetFailureDoesNotLeaveMachineIDDurablyPresentWithoutSource proves the
// crash-safety invariant: MACHINE_ID must never become durably visible before MACHINE_ID_SOURCE
// does. If persisting the source fails, the id must not be persisted either, so a later resolution
// re-derives both together instead of reusing an id whose source was never recorded.
func TestAcceptance_SourceSetFailureDoesNotLeaveMachineIDDurablyPresentWithoutSource(t *testing.T) {
	config := newIsolatedConfig(t)
	failing := &keyFailingStorage{Storage: config.GetStorage(), failKey: configuration.MACHINE_ID_SOURCE}
	config.SetStorage(failing)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLogger(&logger)))

	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	stored := readSnykJSON(t)
	_, sourceDurablyPresent := stored[configuration.MACHINE_ID_SOURCE]
	require.False(t, sourceDurablyPresent, "the source failed to persist")
	_, idDurablyPresent := stored[configuration.MACHINE_ID]
	require.False(t, idDurablyPresent, "the id must not be durably persisted when its source failed to persist")
	require.Contains(t, logs.String(), "simulated storage failure", "the swallowed storage.Set failure must be logged")

	// A later run opens a fresh Configuration against the same underlying file.
	second := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	second.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	value, err := second.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))

	stored = readSnykJSON(t)
	require.Equal(t, id, stored[configuration.MACHINE_ID])
	require.NotEmpty(t, stored[configuration.MACHINE_ID_SOURCE], "the source must be persisted alongside the id once the fresh resolution succeeds")
}

type countingStorage struct {
	configuration.Storage
	locks int32
}

func (c *countingStorage) Lock(ctx context.Context, retryDelay time.Duration) error {
	atomic.AddInt32(&c.locks, 1)
	return c.Storage.Lock(ctx, retryDelay)
}

func TestAcceptance_NoFurtherIOAfterFirstResolution(t *testing.T) {
	config := newIsolatedConfig(t)
	counting := &countingStorage{Storage: config.GetStorage()}
	config.SetStorage(counting)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	afterFirst := atomic.LoadInt32(&counting.locks)
	require.Equal(t, int32(1), afterFirst)

	paths := sharedFilePaths()
	info, statErr := os.Stat(paths.perUser)
	var mtimeAfterFirst time.Time
	if statErr == nil {
		mtimeAfterFirst = info.ModTime()
	}

	_, err = config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, afterFirst, atomic.LoadInt32(&counting.locks), "a second resolution must not touch storage again")

	if statErr == nil {
		info, err = os.Stat(paths.perUser)
		require.NoError(t, err)
		require.Equal(t, mtimeAfterFirst, info.ModTime(), "a second resolution must not rewrite the shared file")
	}
}

// TestAcceptance_SharedFileSchemaFieldsAreStamped proves a freshly written shared file carries the
// bookkeeping fields every reader can rely on: which schema shape it is, whether it was written
// machine-wide or per-user, when the value was first seen and last updated, and which product wrote
// it.
func TestAcceptance_SharedFileSchemaFieldsAreStamped(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	paths := sharedFilePaths()
	writePath := selectWritePath(paths, nil)
	data, err := os.ReadFile(writePath)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))

	require.InDelta(t, float64(schemaVersion), raw["schema_version"], 0)
	// Which scope gets stamped follows selectWritePath's own platform-dependent choice: it is
	// scopeMachine only when the machine-wide directory won (see writeSharedFileValue's createDir
	// parameter), otherwise scopeUser.
	expectedScope := scopeUser
	if writePath == paths.machineWide {
		expectedScope = scopeMachine
	}
	require.Equal(t, expectedScope, raw["scope"])
	require.Equal(t, defaultWriterIdentity, raw["writer"])
	firstSeenAt, ok := raw["first_seen_at"].(string)
	require.True(t, ok)
	_, err = time.Parse(time.RFC3339, firstSeenAt)
	require.NoError(t, err)
	updatedAt, ok := raw["updated_at"].(string)
	require.True(t, ok)
	_, err = time.Parse(time.RFC3339, updatedAt)
	require.NoError(t, err)
}

// TestAcceptance_SharedFileWriteRecordsRuntimeInfoAsWriter proves WithRuntimeInfo's value ends up
// in the shared file's writer field, so a machine carrying values written by several different
// products or versions is identifiable.
func TestAcceptance_SharedFileWriteRecordsRuntimeInfoAsWriter(t *testing.T) {
	config := newIsolatedConfig(t)
	ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.2.3"))
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithRuntimeInfo(ri)))
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	sf := readSharedFile(sharedFilePaths(), nil)
	require.NotNil(t, sf)
	require.Equal(t, "snyk-cli/1.2.3", sf.Writer)
}

// TestAcceptance_SharedFileWritePreservesUnknownFields proves a write this package makes does not
// clobber fields it does not itself model: serial_number and hostname may be populated by other
// Snyk tooling, and a future schema version may add fields this build of the package has never
// heard of, so a merge write must leave both untouched.
func TestAcceptance_SharedFileWritePreservesUnknownFields(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	preseeded := map[string]any{
		"serial_number": "5CG1234ABC",
		"hostname":      "some-host",
		"a_future_field_this_version_does_not_know_about": "keep-me",
	}
	data, err := json.Marshal(preseeded)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o600))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err = config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	data, err = os.ReadFile(paths.perUser)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Equal(t, "5CG1234ABC", raw["serial_number"])
	require.Equal(t, "some-host", raw["hostname"])
	require.Equal(t, "keep-me", raw["a_future_field_this_version_does_not_know_about"])
}

// TestAcceptance_PerUserDirBlockedByExistingFileDoesNotPreventResolution proves resolution
// degrades gracefully when the per-user shared-file directory's parent is occupied by a plain file
// rather than a directory (a layout an older Snyk product may have left behind): the shared file
// write is skipped, but resolution still succeeds and still persists to configuration storage.
func TestAcceptance_PerUserDirBlockedByExistingFileDoesNotPreventResolution(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	blockingParent := filepath.Dir(filepath.Dir(paths.perUser))
	require.NoError(t, os.MkdirAll(filepath.Dir(blockingParent), 0o755))
	require.NoError(t, os.WriteFile(blockingParent, []byte("not a directory"), 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, valid(id))
	require.Equal(t, string(sourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, id, readSnykJSON(t)[configuration.MACHINE_ID])
}
