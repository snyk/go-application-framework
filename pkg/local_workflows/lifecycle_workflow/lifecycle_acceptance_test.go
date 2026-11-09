package lifecycle_workflow_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	lifecycle "github.com/snyk/go-application-framework/pkg/local_workflows/lifecycle_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// newEngine returns an initialized engine with the lifecycle workflows and the steps that register adds.
func newEngine(t *testing.T, register func(engine workflow.Engine)) workflow.Engine {
	t.Helper()
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, lifecycle.InitLifecycleWorkflows(engine))
	register(engine)
	require.NoError(t, engine.Init())
	return engine
}

// registerStep registers a workflow labeled with the lifecycle and returns its ID.
func registerStep(t *testing.T, engine workflow.Engine, name string, step catalog.Lifecycle, callback workflow.Callback) workflow.Identifier {
	t.Helper()
	id := workflow.NewWorkflowIdentifier(name)
	options := workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet(name, pflag.ContinueOnError))
	_, err := catalog.Register(engine, id, options, callback, catalog.WithLifecycle(step))
	require.NoError(t, err)
	return id
}

// recorder returns a step that appends its name to ran and succeeds.
func recorder(ran *[]string, name string) workflow.Callback {
	return func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		*ran = append(*ran, name)
		return nil, nil
	}
}

// Acceptance: install runs every workflow labeled lifecycle=install, in ID order, and never an uninstall step.
func Test_Install_RunsEveryInstallStepInIDOrder(t *testing.T) {
	var ran []string
	engine := newEngine(t, func(engine workflow.Engine) {
		registerStep(t, engine, "lifecycle zeta", catalog.Install, recorder(&ran, "zeta"))
		registerStep(t, engine, "lifecycle alpha", catalog.Install, recorder(&ran, "alpha"))
		registerStep(t, engine, "lifecycle omega", catalog.Uninstall, recorder(&ran, "omega"))
	})

	output, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL)
	require.NoError(t, err)
	assert.Nil(t, output)
	assert.Equal(t, []string{"alpha", "zeta"}, ran)
}

// Acceptance: uninstall runs only the workflows labeled lifecycle=uninstall.
func Test_Uninstall_RunsOnlyUninstallSteps(t *testing.T) {
	var ran []string
	engine := newEngine(t, func(engine workflow.Engine) {
		registerStep(t, engine, "lifecycle install step", catalog.Install, recorder(&ran, "install"))
		registerStep(t, engine, "lifecycle uninstall step", catalog.Uninstall, recorder(&ran, "uninstall"))
	})

	_, err := engine.Invoke(lifecycle.WORKFLOWID_UNINSTALL)
	require.NoError(t, err)
	assert.Equal(t, []string{"uninstall"}, ran)
}

// Acceptance: a failing step and a panicking step do not stop the other steps. Install returns one error that lists each
// failed step as "<step ID>: <message>". A panic is reported by its type only.
func Test_Install_ReturnsOneErrorListingFailedSteps(t *testing.T) {
	var ran []string
	var failing, panicking workflow.Identifier
	engine := newEngine(t, func(engine workflow.Engine) {
		failing = registerStep(t, engine, "lifecycle a failing", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			return nil, errors.New("boom")
		})
		panicking = registerStep(t, engine, "lifecycle b panicking", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			panic("kaboom")
		})
		registerStep(t, engine, "lifecycle c fine", catalog.Install, recorder(&ran, "fine"))
	})

	_, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "SNYK-CLI-0038", catalogErr.ErrorCode)
	assert.Equal(t, "Install or uninstall failed", catalogErr.Title)
	assert.Equal(t,
		failing.String()+": boom\n"+panicking.String()+": workflow callback panicked (string)",
		catalogErr.Detail)
	assert.Equal(t, []string{"fine"}, ran)
}

// Acceptance: the failed-step list names the cause of each failed step. A Snyk error-catalog error contributes its title and
// detail, and any other error its message.
func Test_Install_ListsTheCauseOfEachFailedStep(t *testing.T) {
	var catalogStep, plainStep workflow.Identifier
	engine := newEngine(t, func(engine workflow.Engine) {
		catalogStep = registerStep(t, engine, "lifecycle a catalog", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			return nil, snyk_errors.Error{Title: "Access expired", Detail: "the organization access expired"}
		})
		plainStep = registerStep(t, engine, "lifecycle b plain", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			return nil, errors.New("disk full")
		})
	})

	_, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t,
		catalogStep.String()+": Access expired: the organization access expired\n"+plainStep.String()+": disk full",
		catalogErr.Detail)
}

// Acceptance: the original errors of the failed steps stay reachable from the error that install returns, with errors.Is and
// errors.As. A panic is reachable as its PanicError.
func Test_Install_KeepsTheOriginalErrorsOfFailedSteps(t *testing.T) {
	sentinel := errors.New("sentinel failure")
	engine := newEngine(t, func(engine workflow.Engine) {
		registerStep(t, engine, "lifecycle a wrapped", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			return nil, fmt.Errorf("step: %w", sentinel)
		})
		registerStep(t, engine, "lifecycle b panicking", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			panic("kaboom")
		})
	})

	_, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL)
	require.ErrorIs(t, err, sentinel)
	var panicErr *catalog.PanicError
	require.ErrorAs(t, err, &panicErr)
	assert.Equal(t, "kaboom", panicErr.Value)
}

// Acceptance: a step that does not run because the invocation was canceled is listed as failed, with the context error.
func Test_Install_ListsStepsNotRunBecauseOfCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ran []string
	var second workflow.Identifier
	engine := newEngine(t, func(engine workflow.Engine) {
		registerStep(t, engine, "lifecycle a cancels", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			cancel()
			return nil, nil
		})
		second = registerStep(t, engine, "lifecycle b not run", catalog.Install, recorder(&ran, "second"))
	})

	_, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL, workflow.WithContext(ctx))
	require.ErrorIs(t, err, context.Canceled)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, second.String()+": not run: context canceled", catalogErr.Detail)
	assert.Empty(t, ran)
}

// Acceptance: install returns nil when there are no steps or when every step succeeds. The output data of a step is dropped.
func Test_Install_ReturnsNilWhenNoStepFails(t *testing.T) {
	tests := map[string]func(t *testing.T, engine workflow.Engine){
		"no steps": func(*testing.T, workflow.Engine) {},
		"steps succeed and return data": func(t *testing.T, engine workflow.Engine) {
			t.Helper()
			registerStep(t, engine, "lifecycle with output", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
				output := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("lifecycle output"), "output"), "text/plain", "data")
				return []workflow.Data{output}, nil
			})
		},
	}
	for name, register := range tests {
		t.Run(name, func(t *testing.T) {
			engine := newEngine(t, func(engine workflow.Engine) { register(t, engine) })

			output, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL)
			require.NoError(t, err)
			assert.Nil(t, output)
		})
	}
}

// Acceptance: install and uninstall are known commands for analytics once the production Init registers them.
func Test_InstallAndUninstall_AreKnownCommandsForAnalytics(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, localworkflows.Init(engine))
	require.NoError(t, engine.Init())

	assert.Equal(t, []string{"install"}, instrumentation.DetermineCategory([]string{"snyk", "install"}, engine))
	assert.Equal(t, []string{"uninstall"}, instrumentation.DetermineCategory([]string{"snyk", "uninstall"}, engine))
}
