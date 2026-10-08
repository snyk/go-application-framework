package machineid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSharedFilePathsArePinnedPerOS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	perUser := filepath.Join(home, ".snyk", "machine-id.json")

	t.Run("linux", func(t *testing.T) {
		require.Equal(t, pathPair{
			machineWide: "/etc/snyk/machine-id.json",
			perUser:     perUser,
		}, sharedFilePathsFor("linux"))
	})
	t.Run("darwin", func(t *testing.T) {
		require.Equal(t, pathPair{
			machineWide: "/Library/Application Support/Snyk/machine-id.json",
			perUser:     perUser,
		}, sharedFilePathsFor("darwin"))
	})
	t.Run("windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("filepath only builds windows paths on windows")
		}
		t.Setenv("ProgramData", `C:\ProgramData`)
		t.Setenv("LOCALAPPDATA", `C:\Users\someone\AppData\Local`)
		require.Equal(t, pathPair{
			machineWide: `C:\ProgramData\Snyk\machine-id.json`,
			perUser:     `C:\Users\someone\AppData\Local\Snyk\machine-id.json`,
		}, sharedFilePathsFor("windows"))
	})
}

func TestSharedFilePathsSkipUnsetBaseLocations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("ProgramData", "")
		t.Setenv("LOCALAPPDATA", "")
		require.Equal(t, pathPair{}, defaultSharedFilePaths())
		return
	}
	t.Setenv("HOME", "")

	require.Empty(t, defaultSharedFilePaths().perUser)
}

func tempPaths(t *testing.T) pathPair {
	t.Helper()
	return pathPair{
		machineWide: filepath.Join(t.TempDir(), "machine", "machine-id.json"),
		perUser:     filepath.Join(t.TempDir(), "user", ".snyk", "machine-id.json"),
	}
}

func seed(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func probeRead(path string) error {
	_, err := os.ReadFile(path)
	return err
}

func probeWrite(dir string) error {
	f, err := os.CreateTemp(dir, "probe-*")
	if err != nil {
		return err
	}
	_ = f.Close()
	return os.Remove(f.Name())
}

// skipIfStillAccessible skips when the restriction did not take, e.g. when running as root.
func skipIfStillAccessible(t *testing.T, probe func() error) {
	t.Helper()
	if probe() == nil {
		t.Skip("permissions do not restrict this user")
	}
}

var brokenFiles = map[string]string{
	"unparsable": "{not json",
	"null":       "null",
	"array":      `["some-id"]`,
	"string":     `"some-id"`,
	"number":     "42",
	"blank id":   `{"machine_id": "  "}`,
	"invalid id": `{"machine_id": "not a valid id"}`,
	"oversized":  `{"machine_id": "some-id", "padding": "` + strings.Repeat("a", maxIDFileSize) + `"}`,
}

func TestReadSharedFilePrefersMachineWide(t *testing.T) {
	paths := tempPaths(t)
	seed(t, paths.machineWide, `{"machine_id": "machine-wide-id"}`)
	seed(t, paths.perUser, `{"machine_id": "per-user-id"}`)

	require.Equal(t, "machine-wide-id", readSharedFile(paths, nil).MachineID)
}

func TestReadSharedFileSkipsAMachineWideFileWithoutAValidID(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"missing": func(*testing.T, string) {},
		"unreadable": func(t *testing.T, path string) {
			t.Helper()
			seed(t, path, `{"machine_id": "machine-wide-id"}`)
			makeUnreadable(t, path)
		},
	}
	for name, content := range brokenFiles {
		cases[name] = func(t *testing.T, path string) {
			t.Helper()
			seed(t, path, content)
		}
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			paths := tempPaths(t)
			prepare(t, paths.machineWide)
			seed(t, paths.perUser, `{"machine_id": "per-user-id"}`)
			var logs bytes.Buffer
			logger := zerolog.New(&logs)

			require.Equal(t, "per-user-id", readSharedFile(paths, &logger).MachineID)
			require.Contains(t, logs.String(), jsonEscaped(t, paths.machineWide))
		})
	}
}

func TestReadSharedFileAcceptsAValidIDBesideAFieldOfTheWrongType(t *testing.T) {
	paths := tempPaths(t)
	seed(t, paths.machineWide, `{"machine_id": "machine-wide-id", "schema_version": "1"}`)

	require.Equal(t, "machine-wide-id", readSharedFile(paths, nil).MachineID)
}

func TestReadSharedFileReturnsNilWhenNoFileHoldsAValidID(t *testing.T) {
	require.Nil(t, readSharedFile(tempPaths(t), nil))
}

func write(t *testing.T, paths pathPair, candidate string) string {
	t.Helper()
	id, err := writeSharedFileID(paths, candidate, "generated", "test-writer", nil)
	require.NoError(t, err)
	return id
}

func readFile(t *testing.T, path string) sharedFile {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var sf sharedFile
	require.NoError(t, json.Unmarshal(data, &sf))
	return sf
}

// jsonEscaped returns path as it appears inside a JSON log line, where Windows backslashes are doubled.
func jsonEscaped(t *testing.T, path string) string {
	t.Helper()
	b, err := json.Marshal(path)
	require.NoError(t, err)
	return string(b[1 : len(b)-1])
}

func shortenLockTimeout(t *testing.T) {
	t.Helper()
	original := lockTimeout
	lockTimeout = 50 * time.Millisecond
	t.Cleanup(func() { lockTimeout = original })
}

func holdLock(t *testing.T, path string) {
	t.Helper()
	lock := flock.New(path + ".lock")
	locked, err := lock.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	t.Cleanup(func() { _ = lock.Unlock() }) //nolint:errcheck // best-effort release of the test's own lock
}

func TestWriteSharedFileIDWritesMachineWideWhenItsDirectoryIsWritable(t *testing.T) {
	paths := tempPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))

	id, err := writeSharedFileID(paths, "new-id", "persisted", "some-product/1.2.3", nil)

	require.NoError(t, err)
	require.Equal(t, "new-id", id)
	sf := readFile(t, paths.machineWide)
	require.Equal(t, "new-id", sf.MachineID)
	require.Equal(t, "persisted", sf.IdentifierSource)
	require.Equal(t, 1, sf.SchemaVersion)
	require.Equal(t, "machine", sf.Scope)
	require.Equal(t, "some-product/1.2.3", sf.Writer)
	for _, stamp := range []string{sf.FirstSeenAt, sf.UpdatedAt} {
		_, err := time.Parse(time.RFC3339, stamp)
		require.NoError(t, err)
	}
	require.NoFileExists(t, paths.perUser)
}

func TestWriteSharedFileIDWritesPerUserWithoutCreatingAMissingMachineWideDirectory(t *testing.T) {
	paths := tempPaths(t)

	require.Equal(t, "new-id", write(t, paths, "new-id"))

	require.NoDirExists(t, filepath.Dir(paths.machineWide))
	sf := readFile(t, paths.perUser)
	require.Equal(t, "new-id", sf.MachineID)
	require.Equal(t, "user", sf.Scope)
}

func TestWriteSharedFileIDWritesPerUserWhenMachineWideIsEmpty(t *testing.T) {
	paths := tempPaths(t)
	paths.machineWide = ""

	require.Equal(t, "new-id", write(t, paths, "new-id"))

	require.Equal(t, "new-id", readFile(t, paths.perUser).MachineID)
}

func TestWriteSharedFileIDWritesPerUserWhenMachineWideDirectoryIsNotWritable(t *testing.T) {
	paths := tempPaths(t)
	dir := filepath.Dir(paths.machineWide)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	makeUnwritable(t, dir)

	require.Equal(t, "new-id", write(t, paths, "new-id"))

	require.NoFileExists(t, paths.machineWide)
	require.Equal(t, "new-id", readFile(t, paths.perUser).MachineID)
}

func TestWriteSharedFileIDReturnsAValidMachineWideIDFromADirectoryItCannotWrite(t *testing.T) {
	paths := tempPaths(t)
	seed(t, paths.machineWide, `{"machine_id": "existing-id"}`)
	makeUnwritable(t, filepath.Dir(paths.machineWide))

	require.Equal(t, "existing-id", write(t, paths, "candidate-id"))

	require.NoFileExists(t, paths.perUser)
}

func TestWriteSharedFileIDLeavesAValidFileUntouched(t *testing.T) {
	paths := tempPaths(t)
	original := `{"machine_id":"existing-id","writer":"installer","serial_number":"5CG1234ABC","schema_version":"1"}`
	seed(t, paths.machineWide, original)

	require.Equal(t, "existing-id", write(t, paths, "candidate-id"))

	data, err := os.ReadFile(paths.machineWide)
	require.NoError(t, err)
	require.Equal(t, original, string(data))
	require.NoFileExists(t, paths.perUser)
}

func TestWriteSharedFileIDNeverReplacesAFileItCannotRead(t *testing.T) {
	paths := tempPaths(t)
	seed(t, paths.machineWide, `{"machine_id": "original-id"}`)
	restore := makeUnreadable(t, paths.machineWide)

	require.Equal(t, "candidate-id", write(t, paths, "candidate-id"))

	restore()
	require.Equal(t, "original-id", readFile(t, paths.machineWide).MachineID)
	require.Equal(t, "candidate-id", readFile(t, paths.perUser).MachineID)
}

func TestWriteSharedFileIDReplacesABrokenFile(t *testing.T) {
	for name, content := range brokenFiles {
		t.Run(name, func(t *testing.T) {
			paths := tempPaths(t)
			seed(t, paths.machineWide, content)

			require.Equal(t, "new-id", write(t, paths, "new-id"))

			require.Equal(t, "new-id", readFile(t, paths.machineWide).MachineID)
		})
	}
}

func TestWriteSharedFileIDConvergesOnOneIDUnderConcurrentWriters(t *testing.T) {
	paths := tempPaths(t)
	const writers = 8
	ids := make([]string, writers)
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() {
			ids[i], errs[i] = writeSharedFileID(paths, fmt.Sprintf("id-%d", i), "generated", "test-writer", nil)
		})
	}
	wg.Wait()

	for i := range writers {
		require.NoError(t, errs[i])
		require.Equal(t, ids[0], ids[i])
	}
	require.Equal(t, ids[0], readFile(t, paths.perUser).MachineID)
}

func TestReadersNeverSeeATornFileWhileAWriterReplacesIt(t *testing.T) {
	paths := tempPaths(t)
	paths.machineWide = ""
	// Invalid ids (over 128 characters), so writeAt keeps replacing the file instead of keeping it.
	// A torn write shows up as an empty or partial file, so the values need not be large.
	valueA := strings.Repeat("A", 1024)
	valueB := strings.Repeat("B", 1024)
	// Readers can finish before the writer's first write lands, so the file must exist up front.
	_, err := writeSharedFileID(paths, valueA, "generated", "test-writer", nil)
	require.NoError(t, err)

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			candidate := valueA
			if i%2 == 1 {
				candidate = valueB
			}
			_, _ = writeSharedFileID(paths, candidate, "generated", "test-writer", nil) //nolint:errcheck // readers below are under test
		}
	})

	var reads, torn atomic.Int64
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 200 {
				// Skip failed reads: Windows can refuse to open a file while a rename replaces it.
				data, err := os.ReadFile(paths.perUser)
				if err != nil {
					continue
				}
				reads.Add(1)
				var sf sharedFile
				if json.Unmarshal(data, &sf) != nil || (sf.MachineID != valueA && sf.MachineID != valueB) {
					torn.Add(1)
				}
			}
		})
	}
	readers.Wait()
	close(stop)
	writer.Wait()

	require.NotZero(t, reads.Load())
	require.Zero(t, torn.Load())
}

func TestWriteSharedFileIDFallsBackToPerUserWhenTheMachineWideLockIsHeld(t *testing.T) {
	shortenLockTimeout(t)
	paths := tempPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	holdLock(t, paths.machineWide)
	var logs bytes.Buffer
	logger := zerolog.New(&logs)

	id, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", &logger)

	require.NoError(t, err)
	require.Equal(t, "new-id", id)
	require.NoFileExists(t, paths.machineWide)
	require.Equal(t, "new-id", readFile(t, paths.perUser).MachineID)
	require.Contains(t, logs.String(), jsonEscaped(t, paths.machineWide))
}

func TestWriteSharedFileIDFailsWhenBothLocksAreHeld(t *testing.T) {
	shortenLockTimeout(t)
	paths := tempPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.machineWide), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(paths.perUser), 0o755))
	holdLock(t, paths.machineWide)
	holdLock(t, paths.perUser)

	_, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.Error(t, err)
}

func TestWriteSharedFileIDFailsWithBothCausesWhenNoLocationIsWritable(t *testing.T) {
	paths := tempPaths(t)
	seed(t, filepath.Dir(paths.perUser), "")

	_, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.ErrorIs(t, err, fs.ErrNotExist)
	require.ErrorIs(t, err, syscall.ENOTDIR)
}

func TestWriteSharedFileIDFailsWhenMachineWideFailsAndPerUserIsEmpty(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	paths := tempPaths(t)
	paths.perUser = ""

	_, err := writeSharedFileID(paths, "new-id", "generated", "test-writer", nil)

	require.Error(t, err)
	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestWriteSharedFileIDSetsFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows ignores permission bits")
	}
	defer withZeroUmask(t)()
	machine := tempPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(machine.machineWide), 0o755))
	write(t, machine, "machine-id")
	user := tempPaths(t)
	write(t, user, "user-id")

	for path, want := range map[string]os.FileMode{machine.machineWide: 0o644, user.perUser: 0o600} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, want, info.Mode().Perm(), path)
	}
}
