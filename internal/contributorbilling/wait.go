package contributorbilling

import "time"

// WaitBudget returns a teardown wait duration large enough for one emit call that POSTs
// itemCount entities sequentially, each with its own perRequestTimeout budget.
func WaitBudget(itemCount int, perRequestTimeout time.Duration) time.Duration {
	if itemCount <= 0 {
		itemCount = 1
	}
	if perRequestTimeout <= 0 {
		perRequestTimeout = DefaultTimeout
	}

	return time.Duration(itemCount) * perRequestTimeout
}

// Wait blocks until all in-flight EmitContributorBilling goroutines on the package default Emitter complete.
// Prefer NewEmitter().Wait() when tracking emits on a dedicated instance.
func Wait() {
	defaultEmitter.Wait()
}

// WaitWithTimeout waits up to d for in-flight emits on the package default Emitter to complete.
// Returns true if all completed, false if d elapsed first.
// A non-positive d waits indefinitely, matching Wait().
// For multi-item emits, use WaitBudget(len(items), opts.Timeout) instead of DefaultTimeout alone.
func WaitWithTimeout(d time.Duration) bool {
	return defaultEmitter.WaitWithTimeout(d)
}
