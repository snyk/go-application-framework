package clibilling_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/contributorbilling"
	"github.com/snyk/go-application-framework/pkg/clibilling"
)

func TestBillingEmitter_returnsSharedDefault(t *testing.T) {
	t.Parallel()

	assert.Same(t, contributorbilling.BillingEmitter(), clibilling.BillingEmitter())
}

func TestWaitBudget_delegatesToContributorbilling(t *testing.T) {
	t.Parallel()

	timeout := 2 * time.Second
	assert.Equal(
		t,
		contributorbilling.WaitBudget(3, timeout),
		clibilling.WaitBudget(3, timeout),
	)
}
