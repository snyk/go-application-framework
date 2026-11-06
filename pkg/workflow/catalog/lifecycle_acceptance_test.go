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

func registerStep(t *testing.T, engine workflow.Engine, name string, callback workflow.Callback) workflow.Identifier {
	t.Helper()
	id := workflow.NewWorkflowIdentifier(name)
	_, err := catalog.Register(engine, id, configOptions(), callback, catalog.WithLifecycle(catalog.Install))
	require.NoError(t, err)
	return id
}

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

func invokeRunner(t *testing.T, engine workflow.Engine, opts ...workflow.EngineInvokeOption) ([]catalog.StepFailure, error) {
	t.Helper()
	runnerID, failures := registerRunner(t, engine)
	require.NoError(t, engine.Init())
	_, err := engine.Invoke(runnerID, opts...)
	return *failures, err
}

func failureLines(failures []catalog.StepFailure) []string {
	lines := make([]string, 0, len(failures))
	for _, failure := range failures {
		lines = append(lines, failure.ID.String()+": "+failure.Err.Error())
	}
	return lines
}

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
		"no user interface": func(t *testing.T, engine workflow.Engine) {
			t.Helper()
			engine.SetUserInterface(nil)
			registerStep(t, engine, "lifecycle alpha", noopCallback)
		},
		"progress without a terminal": func(t *testing.T, engine workflow.Engine) {
			t.Helper()
			engine.SetUserInterface(consoleui.New(consoleui.WithProgressWriter(&bytes.Buffer{})))
			registerStep(t, engine, "lifecycle alpha", noopCallback)
			registerStep(t, engine, "lifecycle zeta", noopCallback)
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

func Test_RunLifecycle_StepQueryingCatalogDoesNotDeadlock(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	var seen []string
	alpha := registerStep(t, engine, "lifecycle alpha", func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		seen = idStrings(catalog.FindByLifecycle(ic.GetEngine(), catalog.Install))
		return nil, nil
	})
	zeta := registerStep(t, engine, "lifecycle zeta", noopCallback)
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
