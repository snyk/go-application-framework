package lifecycle_workflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	lifecycle "github.com/snyk/go-application-framework/pkg/local_workflows/lifecycle_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

func newEngine(t *testing.T, register func(engine workflow.Engine)) workflow.Engine {
	t.Helper()
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, lifecycle.InitLifecycleWorkflows(engine))
	register(engine)
	require.NoError(t, engine.Init())
	return engine
}

func registerStep(t *testing.T, engine workflow.Engine, name string, step catalog.Lifecycle, callback workflow.Callback) workflow.Identifier {
	t.Helper()
	id := workflow.NewWorkflowIdentifier(name)
	options := workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet(name, pflag.ContinueOnError))
	_, err := catalog.Register(engine, id, options, callback, catalog.WithLifecycle(step))
	require.NoError(t, err)
	return id
}

func recorder(ran *[]string, name string) workflow.Callback {
	return func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
		*ran = append(*ran, name)
		return nil, nil
	}
}

func Test_LifecycleWorkflows_RunOnlyTheirOwnStepsInIDOrder(t *testing.T) {
	tests := []struct {
		name     string
		workflow workflow.Identifier
		want     []string
	}{
		{"install", lifecycle.WORKFLOWID_INSTALL, []string{"install-a", "install-z"}},
		{"uninstall", lifecycle.WORKFLOWID_UNINSTALL, []string{"uninstall-a", "uninstall-z"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ran []string
			engine := newEngine(t, func(engine workflow.Engine) {
				registerStep(t, engine, "lifecycle install z", catalog.Install, recorder(&ran, "install-z"))
				registerStep(t, engine, "lifecycle uninstall z", catalog.Uninstall, recorder(&ran, "uninstall-z"))
				registerStep(t, engine, "lifecycle install a", catalog.Install, recorder(&ran, "install-a"))
				registerStep(t, engine, "lifecycle uninstall a", catalog.Uninstall, recorder(&ran, "uninstall-a"))
			})

			output, err := engine.Invoke(tt.workflow)
			require.NoError(t, err)
			assert.Nil(t, output)
			assert.Equal(t, tt.want, ran)
		})
	}
}

func Test_Install_ReturnsOneErrorListingFailedSteps(t *testing.T) {
	var ran []string
	var failing, panicking workflow.Identifier
	boom := errors.New("boom")
	engine := newEngine(t, func(engine workflow.Engine) {
		failing = registerStep(t, engine, "lifecycle a failing", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			return nil, boom
		})
		panicking = registerStep(t, engine, "lifecycle b panicking", catalog.Install, func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			panic("kaboom")
		})
		registerStep(t, engine, "lifecycle c fine", catalog.Install, recorder(&ran, "fine"))
	})

	_, err := engine.Invoke(lifecycle.WORKFLOWID_INSTALL)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "SNYK-CLI-0036", catalogErr.ErrorCode)
	assert.Equal(t, "Install or uninstall failed", catalogErr.Title)
	assert.Equal(t,
		failing.String()+": boom\n"+panicking.String()+": workflow callback panicked (string)",
		catalogErr.Detail)
	assert.Equal(t, []string{"fine"}, ran)
	assert.ErrorIs(t, err, boom)
	var panicErr *catalog.PanicError
	require.ErrorAs(t, err, &panicErr)
	assert.Equal(t, "kaboom", panicErr.Value)
}

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
