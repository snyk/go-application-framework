package contributorbilling

import (
	"context"
	"sync"
	"time"
)

// Emitter coordinates fire-and-forget contributor billing POSTs for one host scope.
// Each Emitter owns its own in-flight tracking so Wait/WaitWithTimeout only observe
// emits started on that instance.
type Emitter struct {
	pending inFlightTracker
}

// NewEmitter returns an Emitter with no in-flight work.
func NewEmitter() *Emitter {
	return &Emitter{}
}

// EmitContributorBilling fires an async POST to entitlements-service ingest.
// It returns immediately and never surfaces an error that should fail the caller's command.
// Short-lived hosts (e.g. the CLI) must call Wait or WaitWithTimeout on the same Emitter
// before process exit.
func (e *Emitter) EmitContributorBilling(ctx context.Context, opts EmitOptions) {
	opts = opts.withDefaults()
	opts = ApplyFromConfiguration(opts, opts.Configuration, opts.Engine)
	opts.Items = cloneItems(opts.Items)

	e.pending.add()
	go func(parent context.Context) {
		defer e.pending.done()

		result := emitContributorBilling(parent, opts)
		if opts.OnResult != nil {
			opts.OnResult(result)
		}
	}(ctx)
}

// Wait blocks until all in-flight EmitContributorBilling goroutines on this Emitter complete.
func (e *Emitter) Wait() {
	e.pending.wait()
}

// WaitWithTimeout waits up to d for in-flight emits on this Emitter to complete.
// Returns true if all completed, false if d elapsed first.
// A non-positive d waits indefinitely, matching Wait().
func (e *Emitter) WaitWithTimeout(d time.Duration) bool {
	return e.pending.waitWithTimeout(d)
}

// defaultEmitter backs the package-level helpers. Prefer NewEmitter() for hosts that may
// run multiple workflows or billing scopes in one process (CLI, IDE, MCP).
var defaultEmitter = NewEmitter()

// BillingEmitter returns the package default Emitter for hosts that share one billing scope.
func BillingEmitter() *Emitter {
	return defaultEmitter
}

type inFlightTracker struct {
	mu     sync.Mutex
	count  int
	zeroCh chan struct{}
}

func (t *inFlightTracker) add() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.count == 0 {
		t.zeroCh = make(chan struct{})
	}
	t.count++
}

func (t *inFlightTracker) done() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.count--
	if t.count == 0 && t.zeroCh != nil {
		close(t.zeroCh)
		t.zeroCh = nil
	}
}

func (t *inFlightTracker) snapshot() (count int, zeroCh <-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.count, t.zeroCh
}

func (t *inFlightTracker) wait() {
	for {
		count, ch := t.snapshot()
		if count == 0 {
			return
		}
		if ch == nil {
			continue
		}

		<-ch
	}
}

func (t *inFlightTracker) waitWithTimeout(d time.Duration) bool {
	if d <= 0 {
		t.wait()
		return true
	}

	deadline := time.Now().Add(d)
	for {
		count, ch := t.snapshot()
		if count == 0 {
			return true
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if ch == nil {
			continue
		}

		timer := time.NewTimer(remaining)
		select {
		case <-ch:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			return false
		}
	}
}
