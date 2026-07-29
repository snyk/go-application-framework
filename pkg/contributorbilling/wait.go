package contributorbilling

import "time"

// Wait blocks until all in-flight EmitContributorBilling goroutines on the package default Emitter complete.
func Wait() {
	defaultEmitter.Wait()
}

// WaitWithTimeout waits up to d for in-flight emits on the package default Emitter to complete.
// Returns true if all completed, false if d elapsed first.
// A non-positive d waits indefinitely, matching Wait().
func WaitWithTimeout(d time.Duration) bool {
	return defaultEmitter.WaitWithTimeout(d)
}
