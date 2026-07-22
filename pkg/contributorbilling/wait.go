package contributorbilling

import (
	"sync"
	"time"
)

var pending sync.WaitGroup

// Wait blocks until all in-flight EmitContributorBilling goroutines complete.
func Wait() {
	pending.Wait()
}

// WaitWithTimeout waits up to d for in-flight emits to complete.
// Returns true if all completed, false if d elapsed first.
// A non-positive d waits indefinitely, matching Wait().
func WaitWithTimeout(d time.Duration) bool {
	if d <= 0 {
		pending.Wait()
		return true
	}

	done := make(chan struct{})
	go func() {
		pending.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}
