package clibilling

import (
	"context"
	"sync"
	"time"

	contributorbilling "github.com/snyk/go-application-framework/internal/contributorbilling"
	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const defaultFinalizeWait = 2 * time.Second

type pendingEmit struct {
	mu          sync.Mutex
	emitter     *contributorbilling.Emitter
	recordCount int
}

var commandPendingEmit pendingEmit

// RegisterWithEngine wires contributor billing capture emit-on-first-record and the
// post-invoke wait hook on the engine. Must be called before Init.
func RegisterWithEngine(engine workflow.Engine) {
	capture.RegisterFirstRecordHandler(func() {
		TryEmitAfterFirstCapture(context.Background(), engine, engine.GetConfiguration())
	})
	if err := engine.AddPostInvokeHook(ContributorBillingPostInvokeHook); err != nil {
		engine.GetLogger().Warn().Err(err).Msg("failed to register contributor billing post-invoke hook")
	}
}

// TryEmitAfterFirstCapture starts an async ingest POST for the first captured project ID.
func TryEmitAfterFirstCapture(ctx context.Context, engine workflow.Engine, config configuration.Configuration) {
	if engine == nil || config == nil || !captureEnabled(config) {
		return
	}
	if !capture.IsBillableCommand(ActiveCommand(engine)) {
		return
	}

	commandPendingEmit.mu.Lock()
	if commandPendingEmit.emitter != nil {
		commandPendingEmit.mu.Unlock()
		return
	}
	commandPendingEmit.mu.Unlock()

	bag := capture.ActiveCapture()
	if bag == nil || !bag.HasRecords() {
		return
	}

	scopeID := config.GetString(configuration.ORGANIZATION)
	if scopeID == "" {
		return
	}

	emitter := contributorbilling.NewEmitter()
	logger := engine.GetLogger()
	contributorbilling.EmitFromCaptureFirstRecord(ctx, bag, contributorbilling.FromCaptureOptions{
		Configuration: config,
		Engine:        engine,
		ScopeID:       scopeID,
		RepoPath:      capture.SessionRepoPath(),
		Emitter:       emitter,
		Logger:        logger,
	})

	commandPendingEmit.mu.Lock()
	commandPendingEmit.emitter = emitter
	commandPendingEmit.recordCount = 1
	commandPendingEmit.mu.Unlock()
}

// WaitForPendingEmit waits for any in-flight emit started during capture and clears session state.
func WaitForPendingEmit(ctx context.Context, engine workflow.Engine, config configuration.Configuration) bool {
	_ = ctx

	commandPendingEmit.mu.Lock()
	emitter := commandPendingEmit.emitter
	recordCount := commandPendingEmit.recordCount
	commandPendingEmit.emitter = nil
	commandPendingEmit.recordCount = 0
	commandPendingEmit.mu.Unlock()

	capture.CloseCommandSession()

	if emitter == nil {
		return true
	}

	waitBudget := contributorbilling.WaitBudget(recordCount, contributorbilling.DefaultTimeout)
	if waitBudget <= 0 {
		waitBudget = defaultFinalizeWait
	}
	_ = engine
	_ = config
	return emitter.WaitWithTimeout(waitBudget)
}

// ResetPendingEmitForTest clears in-flight emit tracking. Used by tests.
func ResetPendingEmitForTest() {
	commandPendingEmit.mu.Lock()
	commandPendingEmit.emitter = nil
	commandPendingEmit.recordCount = 0
	commandPendingEmit.mu.Unlock()
}
