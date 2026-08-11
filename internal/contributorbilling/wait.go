package contributorbilling

import "time"

// WaitBudget returns a teardown wait duration for one emit call.
// The timeout parameter covers the HTTP POST; if zero or negative, DefaultTimeout is used.
// Collection overhead (git log, dedup, etc.) is always added.
func WaitBudget(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return timeout
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
