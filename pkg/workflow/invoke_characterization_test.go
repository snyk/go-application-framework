package workflow

import (
	"context"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// noCallbackEntry is an entry whose workflow has no callback.
type noCallbackEntry struct{ Entry }

func (noCallbackEntry) GetEntryPoint() Callback { return nil }

// Test_EngineImpl_Invoke_WorkflowWithoutCallbackRunsNothing pins what an invocation of a workflow without a callback does:
// nothing runs, the invocation has neither output nor error, and the post-invoke hooks still observe that.
func Test_EngineImpl_Invoke_WorkflowWithoutCallbackRunsNothing(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	id := NewWorkflowIdentifier("no.callback")
	_, err := engine.Register(id, ConfigurationOptionsFromFlagset(pflag.NewFlagSet("t", pflag.ContinueOnError)),
		func(_ InvocationContext, _ []Data) ([]Data, error) {
			t.Error("the callback must not run")
			return nil, nil
		})
	require.NoError(t, err)
	engine.(*EngineImpl).workflows[id.String()] = noCallbackEntry{}

	var hookCalls int
	var hookErr error
	require.NoError(t, AddPostInvokeHook(engine, func(_ context.Context, _ Engine, result InvokeOutput) {
		hookCalls++
		hookErr = result.GetError()
	}))
	require.NoError(t, engine.Init())

	output, err := engine.Invoke(id)
	assert.NoError(t, err)
	assert.Empty(t, output)
	assert.Equal(t, 1, hookCalls)
	assert.NoError(t, hookErr)
}

// Test_EngineImpl_Invoke_CallerConfigurationIsUsedAsGiven pins that a configuration passed with WithConfig is the one the
// workflow sees, not a clone of it.
func Test_EngineImpl_Invoke_CallerConfigurationIsUsedAsGiven(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	id := NewWorkflowIdentifier("given.config")
	var seen configuration.Configuration
	_, err := engine.Register(id, ConfigurationOptionsFromFlagset(pflag.NewFlagSet("t", pflag.ContinueOnError)),
		func(ictx InvocationContext, _ []Data) ([]Data, error) {
			seen = ictx.GetConfiguration()
			return nil, nil
		})
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	custom := configuration.NewInMemory()
	_, err = engine.Invoke(id, WithConfig(custom))
	require.NoError(t, err)
	assert.Same(t, custom, seen)
}
