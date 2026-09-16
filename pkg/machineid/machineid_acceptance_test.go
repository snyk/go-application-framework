package machineid

import (
	"context"
	"encoding/json"
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
	require.Equal(t, "legacy-raw-value\n", value, "the identifier has no defined format; whatever parse returns is adopted byte for byte, trailing newline included")
	require.Equal(t, string(SourceLegacy), config.GetString(configuration.MACHINE_ID_SOURCE))
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
