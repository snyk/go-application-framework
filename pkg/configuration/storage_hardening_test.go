package configuration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_JsonStorage_ConcurrentSetsOfOneFileKeepEveryKey writes through several storages of one file at the same time. Each
// Set reads and rewrites the whole file, so the writes must be serialized per file, not per storage.
func Test_JsonStorage_ConcurrentSetsOfOneFileKeepEveryKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "shared.json")
	const writers, keysPerWriter = 4, 50

	var wg sync.WaitGroup
	for w := range writers {
		storage := NewJsonStorage(file)
		wg.Go(func() {
			for i := range keysPerWriter {
				assert.NoError(t, storage.Set(fmt.Sprintf("w%d_%d", w, i), i))
			}
		})
	}
	wg.Wait()

	content, err := os.ReadFile(file)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(content, &doc))
	for w := range writers {
		for i := range keysPerWriter {
			assert.Contains(t, doc, fmt.Sprintf("w%d_%d", w, i), "a write from another storage of the same file was lost")
		}
	}
}

// Test_JsonStorage_DefaultBehavior pins how a storage treats a blank file, numbers and trailing data by default.
func Test_JsonStorage_DefaultBehavior(t *testing.T) {
	dir := t.TempDir()

	t.Run("a blank file fails a persisted write", func(t *testing.T) {
		file := filepath.Join(dir, "blank.json")
		require.NoError(t, os.WriteFile(file, []byte(" \n"), 0o644))
		assert.Error(t, NewJsonStorage(file).Set("a", "x"))
	})

	// A known limitation of the default: the untouched number is rounded. Exact numbers are opt-in, see storage_options_test.go.
	t.Run("numbers are read as float64 and written back rounded", func(t *testing.T) {
		file := filepath.Join(dir, "numbers.json")
		require.NoError(t, os.WriteFile(file, []byte(`{"big":9007199254740993}`), 0o644))
		require.NoError(t, NewJsonStorage(file).Set("other", "x"))
		content, err := os.ReadFile(file)
		require.NoError(t, err)
		assert.JSONEq(t, `{"big":9007199254740992,"other":"x"}`, string(content))
	})

	t.Run("trailing data after the document fails a write", func(t *testing.T) {
		file := filepath.Join(dir, "trailing.json")
		require.NoError(t, os.WriteFile(file, []byte(`{"a":1} {"b":2}`), 0o644))
		assert.Error(t, NewJsonStorage(file).Set("c", "x"))
		content, err := os.ReadFile(file)
		require.NoError(t, err)
		assert.Equal(t, `{"a":1} {"b":2}`, string(content))
	})
}

// Test_JsonStorage_ZeroValueWorks checks that a storage made without NewJsonStorage does not panic on Set.
func Test_JsonStorage_ZeroValueWorks(t *testing.T) {
	var storage JsonStorage
	assert.NotPanics(t, func() { assert.Error(t, storage.Set("a", "x")) })
}
