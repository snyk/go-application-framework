// Package clibilling exposes the minimal CLI orchestration surface for Active Contributor billing emit/wait.
// Capture and middleware wiring live in IANDT-238; cliv2 calls these helpers at command teardown.
package clibilling

import (
	"time"

	"github.com/snyk/go-application-framework/internal/contributorbilling"
)

// DefaultTimeout is the per-request emit timeout when unset.
const DefaultTimeout = contributorbilling.DefaultTimeout

// BillingEmitter returns the shared billing emitter for CLI teardown wait.
func BillingEmitter() *contributorbilling.Emitter {
	return contributorbilling.BillingEmitter()
}

// WaitBudget returns a teardown wait duration for itemCount sequential ingest POSTs.
func WaitBudget(itemCount int, timeout time.Duration) time.Duration {
	return contributorbilling.WaitBudget(itemCount, timeout)
}
