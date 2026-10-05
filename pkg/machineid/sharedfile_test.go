package machineid

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestWriteSharedFileValueAtomicity guards against writeSharedFileValue writing in place
// (open, truncate, write): a reader racing an in-progress write would then be able to
// observe a truncated file, unparsable or holding neither of the two values a writer ever
// wrote. writeSharedFileValue must instead write to a temp file and rename it into place, so
// every read observes either the previous complete value or the next one, never a mix.
func TestWriteSharedFileValueAtomicity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine-id.json")

	valueA := strings.Repeat("A", 64*1024)
	valueB := strings.Repeat("B", 64*1024)

	require.NoError(t, writeSharedFileValue(path, false, "test", func(sf *sharedFile) {
		sf.MachineID = valueA
	}, nil))

	stop := make(chan struct{})
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		toggle := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			v := valueA
			if toggle {
				v = valueB
			}
			toggle = !toggle
			//nolint:errcheck // best-effort background writer racing the readers below; failures are not this test's concern
			_ = writeSharedFileValue(path, false, "test", func(sf *sharedFile) {
				sf.MachineID = v
			}, nil)
		}
	}()

	var readErrs int64
	const readers = 8
	const iterationsPerReader = 2000
	var readerWG sync.WaitGroup
	readerWG.Add(readers)
	for r := 0; r < readers; r++ {
		go func() {
			defer readerWG.Done()
			for i := 0; i < iterationsPerReader; i++ {
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				var sf sharedFile
				if err := json.Unmarshal(data, &sf); err != nil {
					atomic.AddInt64(&readErrs, 1)
					continue
				}
				if sf.MachineID != valueA && sf.MachineID != valueB {
					atomic.AddInt64(&readErrs, 1)
				}
			}
		}()
	}
	readerWG.Wait()
	close(stop)
	writerWG.Wait()

	require.Zero(t, readErrs, "concurrent readers must never observe a torn or invalid write")
}

// TestWriteSharedFileValueDoesNotBlockForeverWhenLockIsHeld guards against writeSharedFileValue's
// flock acquisition blocking indefinitely: a wedged holder of the lock file (a crashed process
// that never released it, for example) must not be able to hang every future resolution forever.
func TestWriteSharedFileValueDoesNotBlockForeverWhenLockIsHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine-id.json")

	held := flock.New(path + ".lock")
	locked, err := held.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	defer func() { _ = held.Unlock() }() //nolint:errcheck // best-effort cleanup of the test's own lock

	original := lockTimeout
	lockTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lockTimeout = original })

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	done := make(chan error, 1)
	go func() {
		done <- writeSharedFileValue(path, false, "test", func(sf *sharedFile) {
			sf.MachineID = "some-id"
		}, &logger)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "writeSharedFileValue must give up once the lock cannot be acquired within lockTimeout")
	case <-time.After(2 * time.Second):
		t.Fatal("writeSharedFileValue did not return: its lock acquisition must be bounded, not block forever")
	}

	require.Contains(t, logs.String(), jsonEscapedPath(t, path), "the swallowed lock timeout must be logged together with the file path")
	require.Contains(t, logs.String(), "lock", "the swallowed lock timeout must be logged")
}

// jsonEscapedPath returns path as zerolog would embed it inside a log line's own quotes: a raw
// Windows path with single backslashes is never a literal substring of JSON-encoded log output,
// which doubles them, so a require.Contains assertion against a logged path must compare against
// this escaped form instead.
func jsonEscapedPath(t *testing.T, path string) string {
	t.Helper()
	b, err := json.Marshal(path)
	require.NoError(t, err)
	return string(b[1 : len(b)-1])
}

// TestSelectWritePathFallsBackToPerUserWhenMachineWideIsEmpty guards against filepath.Dir("")
// resolving to ".": with no machine-wide candidate (e.g. ProgramData unset on Windows),
// selectWritePath must not stat/probe the process's current working directory and mistake a
// writable cwd for a writable machine-wide shared file directory.
func TestSelectWritePathFallsBackToPerUserWhenMachineWideIsEmpty(t *testing.T) {
	perUser := filepath.Join(t.TempDir(), "machine-id.json")

	got := selectWritePath(pathPair{machineWide: "", perUser: perUser}, nil)

	require.Equal(t, perUser, got)
}

// TestDefaultSharedFilePathsNeverProducesARelativePath guards against defaultSharedFilePaths
// returning a path relative to the current working directory when the OS environment it depends
// on (ProgramData/APPDATA on Windows, $HOME elsewhere) is empty or unavailable. A relative path
// would resolve differently depending on the process's working directory, unlike every other
// candidate this package produces.
func TestDefaultSharedFilePathsNeverProducesARelativePath(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Setenv("ProgramData", "")
		t.Setenv("LOCALAPPDATA", "")
	default:
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
	}

	paths := defaultSharedFilePaths()
	for name, p := range map[string]string{"machineWide": paths.machineWide, "perUser": paths.perUser} {
		if p == "" {
			continue
		}
		require.True(t, filepath.IsAbs(p), "%s must be empty or absolute, got relative path %q", name, p)
	}
}

func TestDefaultSharedFilePathsArePinnedPerOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("ProgramData", `C:\ProgramData`)
		t.Setenv("LOCALAPPDATA", `C:\Users\someone\AppData\Local`)
		require.Equal(t, pathPair{
			machineWide: `C:\ProgramData\Snyk\machine-id.json`,
			perUser:     `C:\Users\someone\AppData\Local\Snyk\machine-id.json`,
		}, sharedFilePathsFor("windows"))
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.Equal(t, pathPair{
		machineWide: "/etc/snyk/machine-id.json",
		perUser:     filepath.Join(home, ".snyk", "machine-id.json"),
	}, sharedFilePathsFor("linux"))
	require.Equal(t, pathPair{
		machineWide: "/Library/Application Support/Snyk/machine-id.json",
		perUser:     filepath.Join(home, ".snyk", "machine-id.json"),
	}, sharedFilePathsFor("darwin"))
}

func newTempSharedFilePaths(t *testing.T) pathPair {
	t.Helper()
	return pathPair{
		machineWide: filepath.Join(t.TempDir(), "machine-wide", "Snyk", "machine-id.json"),
		perUser:     filepath.Join(t.TempDir(), "per-user", ".snyk", "machine-id.json"),
	}
}

// newPerUserOnlySharedFilePaths returns paths whose machine-wide parent is a regular file, so the
// machine-wide directory can never be created or written on any OS (on Windows selectWritePath
// would otherwise create it), and every write deterministically lands in the per-user file.
func newPerUserOnlySharedFilePaths(t *testing.T) pathPair {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	return pathPair{
		machineWide: filepath.Join(blocker, "Snyk", "machine-id.json"),
		perUser:     filepath.Join(t.TempDir(), "per-user", ".snyk", "machine-id.json"),
	}
}

func writeRawSharedFile(t *testing.T, path string, content map[string]any) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	data, err := json.Marshal(content)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func readRawSharedFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	return raw
}

func TestReadSharedFilePrefersMachineWide(t *testing.T) {
	paths := newTempSharedFilePaths(t)
	writeRawSharedFile(t, paths.machineWide, map[string]any{"machine_id": "machine-wide-id"})
	writeRawSharedFile(t, paths.perUser, map[string]any{"machine_id": "per-user-id"})

	sf := readSharedFile(paths, nil)

	require.NotNil(t, sf)
	require.Equal(t, "machine-wide-id", sf.MachineID)
}

func TestReadSharedFileSkipsUnusableMachineWideCandidate(t *testing.T) {
	tests := map[string]func(t *testing.T, path string){
		"missing": func(t *testing.T, _ string) { t.Helper() },
		"unparsable": func(t *testing.T, path string) {
			t.Helper()
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
		},
		"blank id": func(t *testing.T, path string) {
			t.Helper()
			writeRawSharedFile(t, path, map[string]any{"machine_id": "  ", "hostname": "some-host"})
		},
		"invalid id": func(t *testing.T, path string) {
			t.Helper()
			writeRawSharedFile(t, path, map[string]any{"machine_id": "not a valid id"})
		},
		"unreadable": func(t *testing.T, path string) {
			t.Helper()
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("file permission bits do not restrict reads for this user")
			}
			writeRawSharedFile(t, path, map[string]any{"machine_id": "machine-wide-id"})
			require.NoError(t, os.Chmod(path, 0o000))
		},
	}
	for name, prepareMachineWide := range tests {
		t.Run(name, func(t *testing.T) {
			paths := newTempSharedFilePaths(t)
			prepareMachineWide(t, paths.machineWide)
			writeRawSharedFile(t, paths.perUser, map[string]any{"machine_id": "per-user-id"})

			var logs bytes.Buffer
			logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

			sf := readSharedFile(paths, &logger)

			require.NotNil(t, sf)
			require.Equal(t, "per-user-id", sf.MachineID)
			require.Contains(t, logs.String(), jsonEscapedPath(t, paths.machineWide), "the skipped machine-wide candidate must be logged with its path")
		})
	}
}

func TestReadSharedFileReturnsNilWhenNoCandidateHoldsAnID(t *testing.T) {
	require.Nil(t, readSharedFile(newTempSharedFilePaths(t), nil))
}

func TestWriteSharedFileIDWritesMachineWideWhenItsDirectoryIsWritable(t *testing.T) {
	if runtime.GOOS != "windows" {
		defer withZeroUmask(t)()
	}
	paths := newTempSharedFilePaths(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))

	id, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.NoError(t, err)
	require.Equal(t, "new-id", id)
	raw := readRawSharedFile(t, paths.machineWide)
	require.Equal(t, "new-id", raw["machine_id"])
	require.Equal(t, "generated", raw["identifier_source"])
	require.Equal(t, scopeMachine, raw["scope"])
	require.Equal(t, "test-writer", raw["writer"])
	require.InDelta(t, float64(schemaVersion), raw["schema_version"], 0)
	for _, field := range []string{"first_seen_at", "updated_at"} {
		stamp, ok := raw[field].(string)
		require.True(t, ok, field)
		_, parseErr := time.Parse(time.RFC3339, stamp)
		require.NoError(t, parseErr, field)
	}
	require.NoFileExists(t, paths.perUser)
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(paths.machineWide)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "the machine-wide file must be readable by every user but writable only by its owner")
	}
}

func TestWriteSharedFileIDWritesPerUserWhenMachineWideDirectoryIsMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on windows the machine-wide directory is created when missing")
	}
	defer withZeroUmask(t)()
	paths := newTempSharedFilePaths(t)

	id, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.NoError(t, err)
	require.Equal(t, "new-id", id)
	require.NoDirExists(t, filepath.Dir(paths.machineWide), "the machine-wide directory must never be created outside windows")
	raw := readRawSharedFile(t, paths.perUser)
	require.Equal(t, "new-id", raw["machine_id"])
	require.Equal(t, scopeUser, raw["scope"])
	info, err := os.Stat(paths.perUser)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "other users must not be able to read the per-user file")
}

func TestWriteSharedFileIDWritesPerUserWhenMachineWideDirectoryIsNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permission bits do not restrict writes for this user")
	}
	paths := newTempSharedFilePaths(t)
	dir := filepath.Dir(paths.machineWide)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) }) //nolint:errcheck // best-effort restore so t.TempDir cleanup can remove dir

	_, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.NoError(t, err)
	require.NoFileExists(t, paths.machineWide)
	require.Equal(t, "new-id", readRawSharedFile(t, paths.perUser)["machine_id"])
}

func TestWriteSharedFileIDFallsBackToPerUserWhenTheMachineWideWriteFails(t *testing.T) {
	paths := newTempSharedFilePaths(t)
	// A directory at the destination passes the directory writability probe but makes the final rename fail.
	require.NoError(t, os.MkdirAll(paths.machineWide, 0o755))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	_, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", &logger)

	require.NoError(t, err)
	require.Equal(t, "new-id", readRawSharedFile(t, paths.perUser)["machine_id"])
	require.Contains(t, logs.String(), jsonEscapedPath(t, paths.machineWide), "the failed machine-wide write must be logged with its path")
}

func TestWriteSharedFileIDFailsWhenNoLocationIsWritable(t *testing.T) {
	paths := newTempSharedFilePaths(t)
	require.NoError(t, os.MkdirAll(paths.machineWide, 0o755))
	blockingParent := filepath.Dir(filepath.Dir(paths.perUser))
	require.NoError(t, os.WriteFile(blockingParent, []byte("not a directory"), 0o600))

	_, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.Error(t, err)
}

func TestWriteSharedFileIDKeepsAnIDAlreadyInTheFile(t *testing.T) {
	paths := newPerUserOnlySharedFilePaths(t)
	writeRawSharedFile(t, paths.perUser, map[string]any{"machine_id": "existing-id", "identifier_source": "anything"})

	id, err := writeSharedFileID(paths, "candidate-id", "generated", "test-writer", nil)

	require.NoError(t, err)
	require.Equal(t, "existing-id", id)
	require.Equal(t, "existing-id", readRawSharedFile(t, paths.perUser)["machine_id"])
}

func TestWriteSharedFileIDPreservesFieldsItDoesNotModel(t *testing.T) {
	paths := newPerUserOnlySharedFilePaths(t)
	writeRawSharedFile(t, paths.perUser, map[string]any{
		"serial_number":     "5CG1234ABC",
		"hostname":          "some-host",
		"a_future_field":    "keep-me",
		"first_seen_at":     "2020-01-01T00:00:00Z",
		"identifier_source": "",
	})

	_, err := writeSharedFileID(paths, "new-id", "persisted", "some-product/1.2.3", nil)

	require.NoError(t, err)
	raw := readRawSharedFile(t, paths.perUser)
	require.Equal(t, "persisted", raw["identifier_source"])
	require.Equal(t, "some-product/1.2.3", raw["writer"])
	require.Equal(t, "5CG1234ABC", raw["serial_number"])
	require.Equal(t, "some-host", raw["hostname"])
	require.Equal(t, "keep-me", raw["a_future_field"])
	require.Equal(t, "2020-01-01T00:00:00Z", raw["first_seen_at"])
}

func TestWriteSharedFileIDTreatsAFileHoldingNonObjectJSONAsAbsent(t *testing.T) {
	for _, content := range []string{"null", "[]", `"x"`, "42"} {
		t.Run(content, func(t *testing.T) {
			paths := newPerUserOnlySharedFilePaths(t)
			require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
			require.NoError(t, os.WriteFile(paths.perUser, []byte(content), 0o600))

			id, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

			require.NoError(t, err)
			require.Equal(t, "new-id", id)
			require.Equal(t, "new-id", readSharedFile(paths, nil).MachineID)
		})
	}
}

func TestDirWritableConcurrentCallsDoNotRace(t *testing.T) {
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
		require.True(t, ok, "call %d: a writable directory must be reported writable even under concurrent calls", i)
	}
}
