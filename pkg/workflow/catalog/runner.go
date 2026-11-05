package catalog

import (
	"fmt"
	"runtime/debug"

	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// StepFailure is a lifecycle step that did not succeed: its ID and the message of its error or panic.
//
// Message is not redacted and is untrusted: the error text of a step can contain any value the step received, such as a
// token. A panic is reported by its type only. Callers must redact Message before they show it to a user, write it to a
// log or send it to analytics.
type StepFailure struct {
	ID      workflow.Identifier
	Message string
}

// RunLifecycle runs every workflow labeled with the lifecycle as a step, in ID order, and returns the steps that failed.
//
// Steps run with their defaults: no input is passed to them. A step that returns an error or panics is recorded, and the
// next step still runs. The output data of a step is dropped. The calling workflow is skipped, so it never runs as a
// step. When the context of the invocation is canceled, the loop stops, and every step that did not run is recorded
// with the message "not run". Progress is reported through the user interface of the invocation, which shows nothing
// without a terminal. RunLifecycle never writes the configuration of the engine.
//
// It returns nil when there are no steps or when every step succeeded.
func RunLifecycle(ic workflow.InvocationContext, lifecycle Lifecycle) []StepFailure {
	engine := ic.GetEngine()
	steps := lifecycleSteps(engine, ic.GetWorkflowIdentifier(), lifecycle)
	if len(steps) == 0 {
		return nil
	}

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
		if err := ic.Context().Err(); err != nil {
			for _, skipped := range steps[i:] {
				failures = append(failures, StepFailure{ID: skipped, Message: "not run: " + err.Error()})
			}
			break
		}
		if err := bar.UpdateProgress(float64(i) / float64(len(steps))); err != nil {
			logger.Debug().Err(err).Msg("cannot update the progress bar")
		}
		if err := runStep(ic, engine, id); err != nil {
			failures = append(failures, StepFailure{ID: id, Message: err.Error()})
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

// runStep invokes one step with no input. The step inherits the context of the invocation, because the engine of the
// invocation context passes it on. Invoke re-raises a panic of the step after the post-invoke hooks ran, so the panic is
// recovered here. The panic value is not reported, because it can carry secrets: only its type is reported, and the
// stack is logged at debug level.
func runStep(ic workflow.InvocationContext, engine workflow.Engine, id workflow.Identifier) (err error) {
	defer func() {
		if r := recover(); r != nil {
			ic.GetEnhancedLogger().Debug().Str("stack", string(debug.Stack())).Msgf("lifecycle step %s panicked", id.String())
			err = fmt.Errorf("workflow callback panicked (%T)", r)
		}
	}()
	_, err = engine.Invoke(id)
	return err
}

// progressBar returns a progress bar of the user interface of the invocation, or an empty one when there is none.
func progressBar(ic workflow.InvocationContext) ui.ProgressBar {
	userInterface := ic.GetUserInterface()
	if userInterface == nil {
		return ui.EmptyProgressBar{}
	}
	return userInterface.NewProgressBar()
}
