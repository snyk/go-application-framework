package catalog

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"

	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// StepFailure is a lifecycle step that did not succeed: its ID and its error.
//
// Err is the original error of the step, so errors.Is and errors.As work on it. A step that panicked has a *PanicError.
// A step that did not run has an error that wraps the context error. The text of Err is not redacted: the error of a step
// can contain any value the step received, such as a token. Callers must redact the text of Err before they show it to a
// user, write it to a log or send it to analytics.
type StepFailure struct {
	ID  workflow.Identifier
	Err error
}

// PanicError is the error of a lifecycle step that panicked. Value is the value the step panicked with.
//
// Its text reports only the type of Value, because a panic value can carry secrets. Value itself is not redacted.
type PanicError struct {
	Value any
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("workflow callback panicked (%T)", e.Value)
}

// RunLifecycle runs every workflow labeled with the lifecycle as a step, in ID order, and returns the steps that failed.
//
// Steps run with their defaults: no input is passed to them. A step that returns an error or panics is recorded, and the
// next step still runs. The output data of a step is dropped. The calling workflow is skipped, so it never runs as a
// step. When the context of the invocation is canceled, the loop stops, and every step that did not run is recorded
// with an error that wraps the context error. Progress is reported through the user interface of the invocation, which
// shows nothing without a terminal. RunLifecycle never writes the configuration of the engine.
//
// A step can invoke the workflow that runs the lifecycle. The steps run in the context of the step, which marks the
// lifecycle as running. A nested RunLifecycle for a lifecycle that is already running in its invocation chain does not run
// the steps again, and returns nil. Independent runs do not affect each other.
//
// It returns nil when there are no steps or when every step succeeded.
func RunLifecycle(ic workflow.InvocationContext, lifecycle Lifecycle) []StepFailure {
	ctx := ic.Context()
	if isRunning(ctx, lifecycle) {
		ic.GetEnhancedLogger().Debug().Msgf("lifecycle %s is already running in this invocation chain, steps not run again", lifecycle)
		return nil
	}

	engine := ic.GetEngine()
	steps := lifecycleSteps(engine, ic.GetWorkflowIdentifier(), lifecycle)
	if len(steps) == 0 {
		return nil
	}
	stepCtx := withRunning(ctx, lifecycle)

	// A failed progress update is logged and does not fail the steps: progress is informative only.
	logger := ic.GetEnhancedLogger()
	bar := progressBar(ic)
	defer func() {
		if err := bar.Clear(); err != nil {
			logger.Debug().Err(err).Msg("cannot clear the progress bar")
		}
	}()
	// The title is set once, before the first progress update: a terminal progress bar reads it from another goroutine.
	bar.SetTitle(fmt.Sprintf("Running %s steps", lifecycle))

	var failures []StepFailure
	for i, id := range steps {
		if err := ctx.Err(); err != nil {
			for _, skipped := range steps[i:] {
				failures = append(failures, StepFailure{ID: skipped, Err: fmt.Errorf("not run: %w", err)})
			}
			break
		}
		if err := bar.UpdateProgress(float64(i) / float64(len(steps))); err != nil {
			logger.Debug().Err(err).Msg("cannot update the progress bar")
		}
		if err := runStep(stepCtx, ic, engine, id); err != nil {
			failures = append(failures, StepFailure{ID: id, Err: err})
		}
	}
	return failures
}

// lifecycleSteps returns the sorted IDs of the workflows labeled with the lifecycle, without the calling workflow.
func lifecycleSteps(engine workflow.Engine, self workflow.Identifier, lifecycle Lifecycle) []workflow.Identifier {
	var steps []workflow.Identifier
	for _, id := range FindByLifecycle(engine, lifecycle) {
		if self != nil && id.String() == self.String() {
			continue
		}
		steps = append(steps, id)
	}
	return steps
}

// runStep invokes one step with no input, on the given context. Invoke re-raises a panic of the step after the post-invoke
// hooks ran, so the panic is recovered here and returned as a PanicError. The stack is logged at debug level.
func runStep(ctx context.Context, ic workflow.InvocationContext, engine workflow.Engine, id workflow.Identifier) (err error) {
	defer func() {
		if r := recover(); r != nil {
			ic.GetEnhancedLogger().Debug().Str("stack", string(debug.Stack())).Msgf("lifecycle step %s panicked", id.String())
			err = &PanicError{Value: r}
		}
	}()
	_, err = engine.Invoke(id, workflow.WithContext(ctx))
	return err
}

// runningKey is the context key of the lifecycles that are running in an invocation chain.
type runningKey struct{}

// isRunning reports whether a run of the lifecycle is already active in the invocation chain of the context.
func isRunning(ctx context.Context, lifecycle Lifecycle) bool {
	return slices.Contains(runningLifecycles(ctx), lifecycle)
}

// withRunning returns a context in which the lifecycle is marked as running. The context of the caller is not changed.
func withRunning(ctx context.Context, lifecycle Lifecycle) context.Context {
	running := append(slices.Clone(runningLifecycles(ctx)), lifecycle)
	return context.WithValue(ctx, runningKey{}, running)
}

// runningLifecycles returns the lifecycles that are running in the invocation chain of the context.
func runningLifecycles(ctx context.Context) []Lifecycle {
	if running, ok := ctx.Value(runningKey{}).([]Lifecycle); ok {
		return running
	}
	return nil
}

// progressBar returns a progress bar of the user interface of the invocation, or an empty one when there is none. The
// engine allows its user interface to be set to nil, so an invocation can have none.
func progressBar(ic workflow.InvocationContext) ui.ProgressBar {
	userInterface := ic.GetUserInterface()
	if userInterface == nil {
		return ui.EmptyProgressBar{}
	}
	return userInterface.NewProgressBar()
}
