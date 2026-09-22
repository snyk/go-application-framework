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

	require.NoError(t, writeSharedFileValue(path, false, func(sf *SharedFile) {
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
			_ = writeSharedFileValue(path, false, func(sf *SharedFile) {
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
				var sf SharedFile
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
		done <- writeSharedFileValue(path, false, func(sf *SharedFile) {
			sf.MachineID = "some-id"
		}, &logger)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "writeSharedFileValue must give up once the lock cannot be acquired within lockTimeout")
	case <-time.After(2 * time.Second):
		t.Fatal("writeSharedFileValue did not return: its lock acquisition must be bounded, not block forever")
	}

	require.Contains(t, logs.String(), path, "the swallowed lock timeout must be logged together with the file path")
	require.Contains(t, logs.String(), "lock", "the swallowed lock timeout must be logged")
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
		t.Setenv("APPDATA", "")
	default:
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
		t.Setenv("XDG_CONFIG_HOME", "")
	}

	paths := defaultSharedFilePaths()
	for name, p := range map[string]string{"machineWide": paths.machineWide, "perUser": paths.perUser} {
		if p == "" {
			continue
		}
		require.True(t, filepath.IsAbs(p), "%s must be empty or absolute, got relative path %q", name, p)
	}
}
