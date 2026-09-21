package machineid

import (
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

func TestAcceptance_ExternalChannelIsAdoptedAndPersisted(t *testing.T) {
	config := newIsolatedConfig(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, "device-managed-id", value)
	require.Equal(t, string(SourceProvided), config.GetString(configuration.MACHINE_ID_SOURCE))
	require.Equal(t, "device-managed-id", readSnykJSON(t)[configuration.MACHINE_ID])

	sf := readSharedFile(sharedFilePaths())
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
	require.Nil(t, readSharedFile(sharedFilePaths()), "OS-derived values must never be written to the shared file")
}

func TestAcceptance_LegacyFileIsUsedWhenOptedIn(t *testing.T) {
	config := newIsolatedConfig(t)
	legacyPath := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(legacyPath, []byte("legacy-raw-value\n"), 0o644))
	parse := func(data []byte) (string, error) { return string(data), nil }

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLegacyDeviceIdFile(legacyPath, parse)))

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

	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(WithLegacyDeviceIdFile(legacyPath, parse)))

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.Equal(t, " \t{ABC-99}\x00WEIRD-interior", value, "only trailing whitespace is removed; leading whitespace, braces, control characters and case are untouched")
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
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	id, ok := value.(string)
	require.True(t, ok)
	require.True(t, hasValue(id))
	require.Equal(t, string(SourceGenerated), config.GetString(configuration.MACHINE_ID_SOURCE))
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

	require.NoError(t, Reset(config))

	require.Empty(t, readSnykJSON(t)[configuration.MACHINE_ID])
	sf := readSharedFile(sharedFilePaths())
	if sf != nil {
		require.Empty(t, sf.MachineID)
	}

	second, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "a resolution after Reset must not reuse the discarded value")
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
	sf := readSharedFile(pathPair{perUser: s.perUserPath})
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

	require.NoError(t, Reset(config))

	require.Equal(t, []string{configuration.MACHINE_ID, configuration.MACHINE_ID_SOURCE}, recording.calls,
		"MACHINE_ID must be deleted from storage before MACHINE_ID_SOURCE")
	require.True(t, recording.fileClearedAtCallFor[configuration.MACHINE_ID],
		"the shared file must already be cleared before storage is touched at all")
	require.True(t, recording.fileClearedAtCallFor[configuration.MACHINE_ID_SOURCE],
		"the shared file must already be cleared before storage is touched at all")
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
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve())

	_, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)

	stored := readSnykJSON(t)
	_, sourceDurablyPresent := stored[configuration.MACHINE_ID_SOURCE]
	require.False(t, sourceDurablyPresent, "the source failed to persist")
	_, idDurablyPresent := stored[configuration.MACHINE_ID]
	require.False(t, idDurablyPresent, "the id must not be durably persisted when its source failed to persist")

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
