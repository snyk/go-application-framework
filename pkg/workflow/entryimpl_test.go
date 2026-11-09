package workflow

import (
	"sync"
	"testing"
)

// Run with -race: visibility is read by lookups while it is set by callers.
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
