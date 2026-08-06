package clibilling

import (
	"context"
	"strings"
	"time"

	contributorbilling "github.com/snyk/go-application-framework/internal/contributorbilling"
	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const defaultFinalizeWait = 2 * time.Second

// finalizeContributorBilling closes the active capture session and, on success, posts captured
// billing entities. Returns false when in-flight ingest work did not finish before the wait budget.
func finalizeContributorBilling(
	ctx context.Context,
	engine workflow.Engine,
	config configuration.Configuration,
	success bool,
) bool {
	bag, repoPath := capture.CloseCommandSession()
	if bag == nil {
		return true
	}
	if !success || !captureEnabled(config) {
		return true
	}

	scopeID := strings.TrimSpace(config.GetString(configuration.ORGANIZATION))
	if scopeID == "" {
		return true
	}

	records := bag.DedupedRecords()
	if len(records) == 0 {
		return true
	}

	emitter := contributorbilling.NewEmitter()
	logger := engine.GetLogger()
	contributorbilling.EmitFromCapture(ctx, bag, contributorbilling.FromCaptureOptions{
		Configuration: config,
		Engine:        engine,
		ScopeID:       scopeID,
		RepoPath:      repoPath,
		Emitter:       emitter,
		Logger:        logger,
	})

	waitBudget := contributorbilling.WaitBudget(len(records), contributorbilling.DefaultTimeout)
	if waitBudget <= 0 {
		waitBudget = defaultFinalizeWait
	}
	return emitter.WaitWithTimeout(waitBudget)
}
