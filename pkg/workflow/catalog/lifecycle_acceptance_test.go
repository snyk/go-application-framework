package catalog_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

// failureLines renders each failure as "<step ID>: <error text>".
func failureLines(failures []catalog.StepFailure) []string {
	lines := make([]string, 0, len(failures))
	for _, failure := range failures {
		lines = append(lines, failure.ID.String()+": "+failure.Err.Error())
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
// errors. The original error is kept, so errors.Is works on it. A panic is reported by its type only, so the panic value
// does not leak through the text, while the value stays reachable through a PanicError. The panic is recovered, so the
// runner returns normally.
func Test_RunLifecycle_FailingAndPanickingStepsDoNotStopOthers(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	boom := errors.New("boom")
	failing := registerStep(t, engine, "lifecycle a failing", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		return nil, boom
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
	require.Len(t, failures, 2)
	assert.ErrorIs(t, failures[0].Err, boom, "the original error must be kept, not only its text")
	var panicErr *catalog.PanicError
	require.ErrorAs(t, failures[1].Err, &panicErr)
	assert.Equal(t, "kaboom", panicErr.Value)
}

// Acceptance: the runner reports no failures when there are no steps, when every step succeeds, or when the steps run
// without a terminal. The output data a step returns is dropped, so it never shows up as a failure.
func Test_RunLifecycle_ReturnsNilWhenNoStepFails(t *testing.T) {
	tests := map[string]func(t *testing.T, engine workflow.Engine){
		"no steps": func(*testing.T, workflow.Engine) {},
		"steps succeed and return data": func(t *testing.T, engine workflow.Engine) {
			t.Helper()
			output := mocks.NewMockData(gomock.NewController(t))
			registerStep(t, engine, "lifecycle with output", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
				return []workflow.Data{output}, nil
			})
		},
		"progress without a terminal": func(t *testing.T, engine workflow.Engine) {
			t.Helper()
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
	require.Len(t, failures, 2)
	assert.ErrorIs(t, failures[0].Err, context.Canceled)
	assert.ErrorIs(t, failures[1].Err, context.Canceled)
}

// Acceptance: a step that invokes the runner again, which runs the lifecycle, does not run the steps a second time. The
// nested run sees that the lifecycle is already running in its invocation chain, so the step does not recurse. The
// counters stop a regression at the second run, so the test fails instead of recursing without end.
func Test_RunLifecycle_StepThatInvokesRunnerRunsEachStepOnce(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	runnerID, failures := registerRunner(t, engine)
	var alphaRuns, zetaRuns int
	var nestedErr error
	registerStep(t, engine, "lifecycle alpha", func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		alphaRuns++
		if alphaRuns > 1 {
			return nil, nil
		}
		_, nestedErr = ic.GetEngine().Invoke(runnerID)
		return nil, nil
	})
	registerStep(t, engine, "lifecycle zeta", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		zetaRuns++
		return nil, nil
	})
	require.NoError(t, engine.Init())

	_, err := engine.Invoke(runnerID)
	require.NoError(t, err)
	require.NoError(t, nestedErr)
	assert.Equal(t, 1, alphaRuns)
	assert.Equal(t, 1, zetaRuns)
	assert.Empty(t, *failures)
}

// Acceptance, run with -race: two independent runs of the lifecycle started at the same time on one engine each run every
// step. The guard against nested runs is per invocation chain, so one run never stops the other.
func Test_RunLifecycle_ConcurrentIndependentRunsEachRunSteps(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	var runs atomic.Int32
	countRun := func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		runs.Add(1)
		return nil, nil
	}
	registerStep(t, engine, "lifecycle alpha", countRun)
	registerStep(t, engine, "lifecycle zeta", countRun)
	runnerID := workflow.NewWorkflowIdentifier("lifecycle runner")
	_, err := engine.Register(runnerID, configOptions(), func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		if len(catalog.RunLifecycle(ic, catalog.Install)) > 0 {
			return nil, errors.New("lifecycle steps failed")
		}
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	var runners sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		runners.Add(1)
		go func() {
			defer runners.Done()
			_, errs[i] = engine.Invoke(runnerID, workflow.WithContext(context.Background()))
		}()
	}
	runners.Wait()

	require.NoError(t, errors.Join(errs...))
	assert.Equal(t, int32(4), runs.Load(), "each of the two runs must run both steps")
}

// Acceptance: the runner works when the engine has no user interface, which the engine allows. The steps run and no
// progress is shown.
func Test_RunLifecycle_WithoutUserInterfaceRunsSteps(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	engine.SetUserInterface(nil)
	var ran int
	registerStep(t, engine, "lifecycle alpha", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		ran++
		return nil, nil
	})

	failures, err := invokeRunner(t, engine)
	require.NoError(t, err)
	assert.Nil(t, failures)
	assert.Equal(t, 1, ran)
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
