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

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// newIsolatedConfig builds a real, file-backed Configuration rooted at a fresh temp HOME, and
// points the shared machine-id file candidates at temp directories no other test can see.
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

	osMachineID = func() (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { osMachineID = osidFallback })

	// The Storage this configuration ends up with locks a file inside this directory; like real
	// CLI installs that have already written something under it, the directory needs to exist
	// before the first Lock, since Lock (unlike Set) does not create it.
	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)

	return configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
}

// osidFallback restores the real OS machine-id lookup after a test overrides it.
var osidFallback = osMachineID

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
	config.Set(configuration.MACHINE_ID_SOURCE, string(SourceGenerated))
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "stored-value-1", value)
	require.Equal(t, string(SourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
}

func TestAcceptance_ValueFoundInSharedFileIsAdopted(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := SharedFile{MachineID: "from-shared-file", IdentifierSource: string(SourceProvided)}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "from-shared-file", value)
	require.Equal(t, string(SourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, "from-shared-file", readSnykJSON(t)[configuration.MACHINE_ID])
}

// TestAcceptance_SharedFileWithUnknownSourceFallsBackToProvided proves the shared file's
// identifier_source field is validated rather than trusted outright: it is untrusted cross-process
// input written by any Snyk product on the machine, unlike the machine id itself, which this
// package deliberately treats as opaque and never validates.
func TestAcceptance_SharedFileWithUnknownSourceFallsBackToProvided(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := SharedFile{MachineID: "from-shared-file", IdentifierSource: "whatever-a-tampered-or-buggy-writer-put-here"}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "from-shared-file", value)
	require.Equal(t, string(SourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAcceptance_MachineWideFileWithNoMachineIDDoesNotShadowPerUserFile proves readSharedFile keeps
// scanning candidates rather than stopping at the first one that merely parses: a machine-wide file
// written by other tooling (per the SharedFile doc comment, serial_number/hostname only, no
// machine_id) must not shadow a per-user file that actually holds the shared id.
func TestAcceptance_MachineWideFileWithNoMachineIDDoesNotShadowPerUserFile(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()

	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	machineWideSF := SharedFile{SerialNumber: "5CG1234ABC", Hostname: "some-host"}
	data, err := json.Marshal(machineWideSF)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.machineWide, data, 0o644))

	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	perUserSF := SharedFile{MachineID: "from-per-user-file", IdentifierSource: string(SourceProvided)}
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

// TestAcceptance_ConcurrentWriterWithUnknownSourceInStorageFallsBackToProvided proves
// mirrorIntoStorage validates identifier_source read back from a concurrent writer's storage
// entry, the same way resolve() validates it when read from the shared file: storage is as
// untrusted as the shared file, since any Snyk product sharing the same configuration file can
// have written it.
func TestAcceptance_ConcurrentWriterWithUnknownSourceInStorageFallsBackToProvided(t *testing.T) {
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
	require.Equal(t, string(SourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
}

// TestAdoptOrWriteSharedFileValidatesRaceWinnersSource proves adoptOrWriteSharedFile validates
// identifier_source the same way resolve() does: a concurrent writer that beat this call to the
// shared file is exactly as untrusted as one whose value was already there when resolve() started.
func TestAdoptOrWriteSharedFileValidatesRaceWinnersSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine-id.json")
	sf := SharedFile{MachineID: "race-winner-id", IdentifierSource: "whatever-a-tampered-or-buggy-writer-put-here"}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))

	id, source, err := adoptOrWriteSharedFile(path, false, "candidate-id", SourceProvided, nil)
	require.NoError(t, err)
	require.Equal(t, "race-winner-id", id)
	require.Equal(t, SourceProvided, source)
}

func TestAcceptance_ExternalChannelIsAdoptedAndPersisted(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "device-managed-id", value)
	require.Equal(t, string(SourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, "device-managed-id", readSnykJSON(t)[configuration.MACHINE_ID])

	sf := readSharedFile(sharedFilePaths(), nil)
	require.NotNil(t, sf)
	require.Equal(t, "device-managed-id", sf.MachineID)
}

func TestAcceptance_OSIdentifierIsUsedAndNotWrittenToSharedFile(t *testing.T) {
	config := newIsolatedConfig(t)
	osMachineID = func() (string, error) { return "os-derived-id", nil }
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "os-derived-id", value)
	require.Equal(t, string(SourceOS), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, "os-derived-id", readSnykJSON(t)[configuration.MACHINE_ID])
	require.Nil(t, readSharedFile(sharedFilePaths(), nil), "OS-derived values must never be written to the shared file")
}

func TestAcceptance_LegacyFileIsUsedWhenOptedIn(t *testing.T) {
	config := newIsolatedConfig(t)
	legacyPath := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(legacyPath, []byte("legacy-raw-value\n"), 0o644))
	parse := func(data []byte) (string, error) { return string(data), nil }

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLegacyDeviceIDFile(legacyPath, parse)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "legacy-raw-value", value, "the legacy file's trailing newline is a file-format artifact, not part of the identifier")
	require.Equal(t, string(SourceLegacy), config.GetString(configuration.MACHINE_ID_SOURCE))
}

func TestAcceptance_LegacyFileOnlyTrimsTrailingWhitespace(t *testing.T) {
	config := newIsolatedConfig(t)
	legacyPath := filepath.Join(t.TempDir(), "device-id")
	raw := " \t{ABC-99}\x00WEIRD-interior\n\n"
	require.NoError(t, os.WriteFile(legacyPath, []byte(raw), 0o644))
	parse := func(data []byte) (string, error) { return string(data), nil }

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLegacyDeviceIDFile(legacyPath, parse)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, " \t{ABC-99}\x00WEIRD-interior", value, "only trailing whitespace is removed; leading whitespace, braces, control characters and case are untouched")
}

// TestAcceptance_LegacyFileParseFailureFallsThroughToGeneratedAndLogsTheError proves a legacy
// device-id file that fails to parse is treated as no source at all (resolution falls through to
// generating a fresh id) while still logging the swallowed parse error and the file's path.
func TestAcceptance_LegacyFileParseFailureFallsThroughToGeneratedAndLogsTheError(t *testing.T) {
	config := newIsolatedConfig(t)
	legacyPath := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(legacyPath, []byte("unparsable-content"), 0o644))
	parseErr := errors.New("simulated legacy file parse failure")
	parse := func(data []byte) (string, error) { return "", parseErr }

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLegacyDeviceIDFile(legacyPath, parse), WithLogger(&logger)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, hasValue(id))
	require.Equal(t, string(SourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))

	require.Contains(t, logs.String(), parseErr.Error(), "the swallowed legacy file parse failure must be logged")
	require.Contains(t, logs.String(), legacyPath, "the swallowed legacy file parse failure must be logged together with its path")
}

func TestAcceptance_ExternalChannelPreservesTrailingWhitespace(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id\n")
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "device-managed-id\n", value, "trailing whitespace is only trimmed from the legacy file path")
}

func TestAcceptance_SharedFilePreservesTrailingWhitespace(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	sf := SharedFile{MachineID: "from-shared-file\n", IdentifierSource: string(SourceProvided)}
	data, err := json.Marshal(sf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.perUser, data, 0o644))

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "from-shared-file\n", value, "trailing whitespace is only trimmed from the legacy file path")
}

func TestAcceptance_OSIdentifierPreservesTrailingWhitespace(t *testing.T) {
	config := newIsolatedConfig(t)
	osMachineID = func() (string, error) { return "os-derived-id\n", nil }
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "os-derived-id\n", value, "trailing whitespace is only trimmed from the legacy file path")
}

func TestAcceptance_ExternalChannelValueIsStoredExactlyAsSupplied(t *testing.T) {
	config := newIsolatedConfig(t)
	braceWrapped := "{550E8400-E29B-41D4-A716-446655440000}"
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", braceWrapped)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, braceWrapped, value, "the identifier has no defined format; it must round-trip exactly as supplied")
	require.Equal(t, braceWrapped, readSnykJSON(t)[configuration.MACHINE_ID])
}

func TestAcceptance_WhitespaceOnlyExternalValueFallsThroughToOS(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "   ")
	osMachineID = func() (string, error) { return "os-derived-id", nil }
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "os-derived-id", value, "a whitespace-only value means the external channel supplied nothing")
	require.Equal(t, string(SourceOS), config.GetString(configuration.MACHINE_ID_SOURCE))
}

func TestAcceptance_GeneratesUUIDWhenNoOtherSourceApplies(t *testing.T) {
	config := newIsolatedConfig(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLogger(&logger)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, hasValue(id))
	require.Equal(t, string(SourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))

	require.Contains(t, logs.String(), os.ErrNotExist.Error(), "the swallowed OS machine id lookup failure must be logged")
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
	require.True(t, hasValue(id))

	require.FileExists(t, paths.perUser, "a write-level failure on the machine-wide path must still fall back to the per-user file")
	require.Contains(t, logs.String(), paths.machineWide, "the swallowed machine-wide shared file write failure must be logged together with its path")
}

// TestAcceptance_SharedFileIsNotWorldWritable proves the machine-wide shared file is written with
// owner-write, group/other-read-only permissions, since any local process being able to rewrite the
// machine identifier is an unnecessary exposure.
func TestAcceptance_SharedFileIsNotWorldWritable(t *testing.T) {
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
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
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
			require.NoError(t, err)
			id, ok := value.(string)
			require.True(t, ok)
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

	require.NoError(t, Reset(config, nil))

	require.Empty(t, readSnykJSON(t)[configuration.MACHINE_ID])
	sf := readSharedFile(sharedFilePaths(), nil)
	if sf != nil {
		require.Empty(t, sf.MachineID)
	}

	second, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "a resolution after Reset must not reuse the discarded value")
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
// shared-file candidate is not discarded when the other also fails: Reset must join both errors,
// not let the second overwrite the first.
//
// This no longer pairs a shared-file failure with a storage-lock failure (see
// TestAcceptance_ResetSurfacesStorageLockErrorWhenSharedFileClearSucceeds): Reset now leaves
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
	// cannot complete for either, forcing two independent, deterministic removal failures.
	require.NoError(t, os.Remove(paths.perUser))
	require.NoError(t, os.Mkdir(paths.perUser, 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	require.NoError(t, os.Mkdir(paths.machineWide, 0o755))

	err = Reset(config, nil)
	require.Error(t, err)
	mu, ok := err.(multiUnwrapper)
	require.True(t, ok, "Reset's error must join both shared-file removal failures, not discard one")
	require.Len(t, mu.Unwrap(), 2)
}

// TestAcceptance_ResetSurfacesStorageLockErrorWhenSharedFileClearSucceeds proves storage.Lock
// failures are still surfaced when they are the only failure: with the shared file clearing
// successfully, Reset must still report a storage-lock failure rather than swallowing it.
func TestAcceptance_ResetSurfacesStorageLockErrorWhenSharedFileClearSucceeds(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	config.SetStorage(&lockFailingStorage{Storage: config.GetStorage()})

	err = Reset(config, nil)
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
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

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
}

// TestAcceptance_ResetDoesNotBlockForeverWhenStorageLockNeverSucceeds proves Reset's storage.Lock
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
		done <- Reset(config, nil)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "Reset must surface the timed-out storage lock as an error")
	case <-time.After(2 * time.Second):
		t.Fatal("Reset did not return: storage.Lock must be bounded by lockTimeout, not block forever on context.Background()")
	}
}

// resetOrderStorage wraps a real Storage and, for every Set call, records the key and whether the
// shared file (at perUserPath) was already cleared at that moment. This proves Reset's actual
// operation order, not just its end state: a concurrent resolve() between Reset's two steps must
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
	s.fileClearedAtCallFor[key] = sf == nil || !hasValue(sf.MachineID)
	return s.Storage.Set(key, value)
}

// TestAcceptance_ResetClearsSharedFileBeforeStorageAndDeletesMachineIDBeforeSource proves Reset's
// two ordering fixes: the shared file is cleared before storage (so a resolve() racing between the
// two steps still sees the old, correct value in storage rather than re-deriving and re-persisting
// it after Reset finishes), and within storage, MACHINE_ID is deleted before MACHINE_ID_SOURCE (the
// mirror image of mirrorIntoStorage's write order, since MACHINE_ID's absence is what a future
// resolve() treats as "not yet resolved").
func TestAcceptance_ResetClearsSharedFileBeforeStorageAndDeletesMachineIDBeforeSource(t *testing.T) {
	config := newIsolatedConfig(t)
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())
	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	paths := sharedFilePaths()
	require.FileExists(t, paths.perUser)

	recording := &resetOrderStorage{
		Storage:              config.GetStorage(),
		perUserPath:          paths.perUser,
		fileClearedAtCallFor: map[string]bool{},
	}
	config.SetStorage(recording)

	require.NoError(t, Reset(config, nil))

	require.Equal(t, []string{configuration.MACHINE_ID, configuration.MACHINE_ID_SOURCE}, recording.calls,
		"MACHINE_ID must be deleted from storage before MACHINE_ID_SOURCE")
	require.True(t, recording.fileClearedAtCallFor[configuration.MACHINE_ID],
		"the shared file must already be cleared before storage is touched at all")
	require.True(t, recording.fileClearedAtCallFor[configuration.MACHINE_ID_SOURCE],
		"the shared file must already be cleared before storage is touched at all")
}

// TestAcceptance_ResetLeavesStorageUntouchedWhenMachineWideFileCannotBeCleared proves the decision
// documented on Reset: when a shared-file candidate cannot be cleared, Reset must not clear storage
// either. readSharedFile checks the machine-wide candidate first, so a stale, still-readable value
// left there by a failed clear would win over anything Reset does to storage on the very next
// resolution; clearing storage anyway would look like Reset succeeded while the effective machine id
// never actually changes, and would additionally throw away the still-valid stored value for no
// benefit.
func TestAcceptance_ResetLeavesStorageUntouchedWhenMachineWideFileCannotBeCleared(t *testing.T) {
	config := newIsolatedConfig(t)
	paths := sharedFilePaths()

	dir := filepath.Dir(paths.machineWide)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, writeSharedFileValue(paths.machineWide, false, func(sf *SharedFile) {
		sf.MachineID = "original-id"
		sf.IdentifierSource = string(SourceOS)
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

	err = Reset(config, nil)
	require.Error(t, err)

	require.Equal(t, "original-id", readSnykJSON(t)[configuration.MACHINE_ID],
		"Reset must leave storage untouched when it cannot clear a shared-file candidate that still holds a value")
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
	require.True(t, hasValue(id))

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
