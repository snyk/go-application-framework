package catalog

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"

	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// StepFailure is a lifecycle step that did not succeed.
//
// Err is the step's original error. A step that panicked has a *PanicError; a step that did not run wraps the context
// error. The text of Err is not redacted and can contain secrets: callers must redact it before showing or logging it.
type StepFailure struct {
	ID  workflow.Identifier
	Err error
}

// PanicError is the error of a lifecycle step that panicked. Its text reports only the type of Value, because a panic
// value can carry secrets.
type PanicError struct {
	Value any
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("workflow callback panicked (%T)", e.Value)
}

// RunLifecycle runs the workflows labeled with the lifecycle in ID order and returns the failed steps, or nil.
//
// Steps get no input and their output is dropped. A failing or panicking step does not stop the next one. The calling
// workflow is skipped, and a nested call for a lifecycle already running in the invocation chain runs nothing.
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

	logger := ic.GetEnhancedLogger()
	bar := progressBar(ic)
	defer func() {
		if err := bar.Clear(); err != nil {
			logger.Debug().Err(err).Msg("cannot clear the progress bar")
		}
	}()
	// set before the first update: the terminal bar reads the title from another goroutine
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

// Invoke re-panics after its hooks ran, so the step's panic is recovered here.
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

type runningKey struct{}

func isRunning(ctx context.Context, lifecycle Lifecycle) bool {
	return slices.Contains(runningLifecycles(ctx), lifecycle)
}

func withRunning(ctx context.Context, lifecycle Lifecycle) context.Context {
	running := append(slices.Clone(runningLifecycles(ctx)), lifecycle)
	return context.WithValue(ctx, runningKey{}, running)
}

func runningLifecycles(ctx context.Context) []Lifecycle {
	if running, ok := ctx.Value(runningKey{}).([]Lifecycle); ok {
		return running
	}
	return nil
}

func progressBar(ic workflow.InvocationContext) ui.ProgressBar {
	userInterface := ic.GetUserInterface()
	if userInterface == nil {
		return ui.EmptyProgressBar{}
	}
	return userInterface.NewProgressBar()
}
