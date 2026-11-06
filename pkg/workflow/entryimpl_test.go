package workflow

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EntryImpl_VisibilityConcurrentAccessDoesNotRace(t *testing.T) {
	entry := &EntryImpl{visible: true}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 1000 {
			entry.SetVisibility(i%2 == 0)
		}
	})
	wg.Go(func() {
		for range 1000 {
			_ = entry.IsVisible()
		}
	})
	wg.Wait()
}

func Test_EntryImpl_ZeroValueSupportsMetadata(t *testing.T) {
	var entry EntryImpl
	assert.NotNil(t, entry.Metadata())
	assert.Empty(t, entry.Metadata())

	require.NoError(t, entry.SetMetadata("key", "value"))
	assert.Equal(t, map[string]any{"key": "value"}, entry.Metadata())
}

func Test_EntryImpl_SetMetadataTwiceKeepsFirstValue(t *testing.T) {
	var entry EntryImpl
	require.NoError(t, entry.SetMetadata("key", "first"))

	require.Error(t, entry.SetMetadata("key", "second"))
	assert.Equal(t, "first", entry.Metadata()["key"])
}

func Test_EntryImpl_MetadataCopyDoesNotChangeEntry(t *testing.T) {
	var entry EntryImpl
	require.NoError(t, entry.SetMetadata("key", "value"))

	copied := entry.Metadata()
	copied["other"] = "x"
	delete(copied, "key")

	assert.Equal(t, map[string]any{"key": "value"}, entry.Metadata())
}

func Test_EntryImpl_MetadataConcurrentAccessDoesNotRace(t *testing.T) {
	entry := &EntryImpl{}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 1000 {
			assert.NoError(t, entry.SetMetadata(fmt.Sprintf("key %d", i), i))
		}
	})
	wg.Go(func() {
		for range 1000 {
			_ = entry.Metadata()
		}
	})
	wg.Wait()

	assert.Len(t, entry.Metadata(), 1000)
}
