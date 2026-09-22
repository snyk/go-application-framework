package machineid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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
	}))

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
			_ = writeSharedFileValue(path, false, func(sf *SharedFile) {
				sf.MachineID = v
			})
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
