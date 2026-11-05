package catalog_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/ui/consoleui"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// registerStep registers a workflow labeled with the lifecycle and returns its ID.
func registerStep(t *testing.T, engine workflow.Engine, name string, callback workflow.Callback) workflow.Identifier {
	t.Helper()
	id := workflow.NewWorkflowIdentifier(name)
	_, err := catalog.Register(engine, id, configOptions(), callback, catalog.WithLifecycle(catalog.Install))
	require.NoError(t, err)
	return id
}

// registerRunner registers a workflow that runs the install steps and records the failures they report. It returns the
// runner ID and the place where the failures are recorded. It must be called before engine.Init.
func registerRunner(t *testing.T, engine workflow.Engine) (workflow.Identifier, *[]catalog.StepFailure) {
	t.Helper()
	runnerID := workflow.NewWorkflowIdentifier("lifecycle runner")
	failures := &[]catalog.StepFailure{}
	_, err := engine.Register(runnerID, configOptions(), func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		*failures = catalog.RunLifecycle(ic, catalog.Install)
		return nil, nil
	})
	require.NoError(t, err)
	return runnerID, failures
}

// invokeRunner runs the install steps through a runner workflow on the test goroutine. It returns the failures the runner
// recorded and the error of the invocation.
func invokeRunner(t *testing.T, engine workflow.Engine, opts ...workflow.EngineInvokeOption) ([]catalog.StepFailure, error) {
	t.Helper()
	runnerID, failures := registerRunner(t, engine)
	require.NoError(t, engine.Init())
	_, err := engine.Invoke(runnerID, opts...)
	return *failures, err
}

// failureLines renders each failure as "<step ID>: <message>".
func failureLines(failures []catalog.StepFailure) []string {
	lines := make([]string, 0, len(failures))
	for _, failure := range failures {
		lines = append(lines, failure.ID.String()+": "+failure.Message)
	}
	return lines
}

// noopStep is a step that succeeds and does nothing.
func noopStep(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
	return nil, nil
}

// Acceptance: the steps run in ID order, each once, and the calling workflow never runs as a step.
func Test_RunLifecycle_RunsStepsInIDOrderAndSkipsCaller(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	var ran []string
	record := func(name string) workflow.Callback {
		return func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			ran = append(ran, name)
			return nil, nil
		}
	}
	registerStep(t, engine, "lifecycle zeta", record("zeta"))
	registerStep(t, engine, "lifecycle alpha", record("alpha"))

	// The runner is labeled too. It records itself and runs the steps only on its first call, so a runner that ran itself
	// would show up as a second "runner" entry instead of recursing.
	runnerID := workflow.NewWorkflowIdentifier("lifecycle runner")
	var failures []catalog.StepFailure
	_, err := catalog.Register(engine, runnerID, configOptions(), func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		ran = append(ran, "runner")
		if len(ran) == 1 {
			failures = catalog.RunLifecycle(ic, catalog.Install)
		}
		return nil, nil
	}, catalog.WithLifecycle(catalog.Install))
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	_, err = engine.Invoke(runnerID)
	require.NoError(t, err)
	assert.Equal(t, []string{"runner", "alpha", "zeta"}, ran)
	assert.Nil(t, failures)
}

// Acceptance: a failing step and a panicking step do not stop the other steps, and both are reported with their IDs and
// messages. A panic is reported by its type only, so the panic value does not leak. The panic is recovered, so the runner
// returns normally.
func Test_RunLifecycle_FailingAndPanickingStepsDoNotStopOthers(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	failing := registerStep(t, engine, "lifecycle a failing", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		return nil, errors.New("boom")
	})
	panicking := registerStep(t, engine, "lifecycle b panicking", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		panic("kaboom")
	})
	var lastRan bool
	registerStep(t, engine, "lifecycle c fine", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		lastRan = true
		return nil, nil
	})

	failures, err := invokeRunner(t, engine)
	require.NoError(t, err)
	assert.True(t, lastRan)
	assert.Equal(t, []string{
		failing.String() + ": boom",
		panicking.String() + ": workflow callback panicked (string)",
	}, failureLines(failures))
}

// Acceptance: the runner reports no failures when there are no steps, when every step succeeds, or when the steps run
// without a terminal. The output data a step returns is dropped, so it never shows up as a failure.
func Test_RunLifecycle_ReturnsNilWhenNoStepFails(t *testing.T) {
	tests := map[string]func(t *testing.T, engine workflow.Engine){
		"no steps": func(*testing.T, workflow.Engine) {},
		"steps succeed and return data": func(t *testing.T, engine workflow.Engine) {
			output := mocks.NewMockData(gomock.NewController(t))
			registerStep(t, engine, "lifecycle with output", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
				return []workflow.Data{output}, nil
			})
		},
		"progress without a terminal": func(t *testing.T, engine workflow.Engine) {
			engine.SetUserInterface(consoleui.New(consoleui.WithProgressWriter(&bytes.Buffer{})))
			registerStep(t, engine, "lifecycle alpha", noopStep)
			registerStep(t, engine, "lifecycle zeta", noopStep)
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
			setup(t, engine)
			failures, err := invokeRunner(t, engine)
			require.NoError(t, err)
			assert.Nil(t, failures)
		})
	}
}

// Acceptance: when the context is canceled while a step runs, the running step sees the cancellation, and the loop stops.
// The steps that did not run are reported as failures.
func Test_RunLifecycle_StopsWhenContextIsCanceledMidStep(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	var ran []string
	var sawCancel bool
	registerStep(t, engine, "lifecycle a blocks", func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		ran = append(ran, "a")
		close(started)
		select {
		case <-ic.Context().Done():
			sawCancel = true
		case <-time.After(5 * time.Second):
		}
		return nil, nil
	})
	beta := registerStep(t, engine, "lifecycle b", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		ran = append(ran, "b")
		return nil, nil
	})
	gamma := registerStep(t, engine, "lifecycle c", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		ran = append(ran, "c")
		return nil, nil
	})
	go func() {
		<-started
		cancel()
	}()

	failures, err := invokeRunner(t, engine, workflow.WithContext(ctx))
	require.NoError(t, err)
	assert.True(t, sawCancel, "the running step must see the cancellation of the invocation")
	assert.Equal(t, []string{"a"}, ran)
	assert.Equal(t, []string{
		beta.String() + ": not run: context canceled",
		gamma.String() + ": not run: context canceled",
	}, failureLines(failures))
}

// Acceptance, run with -race: a step that queries the catalog while the runner runs neither deadlocks nor races, and
// querying the catalog from another goroutine while the runner runs is safe.
func Test_RunLifecycle_StepQueryingCatalogDoesNotDeadlock(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	var seen []string
	alpha := registerStep(t, engine, "lifecycle alpha", func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		seen = idStrings(catalog.FindByLifecycle(ic.GetEngine(), catalog.Install))
		return nil, nil
	})
	zeta := registerStep(t, engine, "lifecycle zeta", noopStep)
	runnerID, failures := registerRunner(t, engine)
	require.NoError(t, engine.Init())

	stop := make(chan struct{})
	var querying sync.WaitGroup
	querying.Add(1)
	defer func() {
		close(stop)
		querying.Wait()
	}()
	go func() {
		defer querying.Done()
		for {
			select {
			case <-stop:
				return
			default:
				catalog.FindByLifecycle(engine, catalog.Install)
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := engine.Invoke(runnerID)
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the runner did not finish: a step that queries the catalog may be deadlocked")
	}

	require.NoError(t, err)
	assert.Empty(t, *failures)
	assert.Equal(t, []string{alpha.String(), zeta.String()}, seen)
}
