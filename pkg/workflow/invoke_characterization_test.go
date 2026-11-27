package workflow

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

// noCallbackEntry is an entry whose workflow has no callback.
type noCallbackEntry struct{ Entry }

func (noCallbackEntry) GetEntryPoint() Callback { return nil }

func Test_EngineImpl_Invoke_WorkflowWithoutCallbackRunsNothing(t *testing.T) {
	engine, id := setupHookTestEngine(t, "no.callback", nil)
	// Register rejects a nil entry point, so the entry is written directly to reach the callback == nil branch.
	impl, ok := engine.(*EngineImpl)
	require.True(t, ok)
	impl.mu.Lock()
	impl.workflows[id.String()] = noCallbackEntry{}
	impl.mu.Unlock()

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

func Test_EngineImpl_Invoke_CallerConfigurationIsUsedAsGiven(t *testing.T) {
	var seen configuration.Configuration
	engine, id := setupHookTestEngine(t, "given.config", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		seen = ictx.GetConfiguration()
		return nil, nil
	})
	require.NoError(t, engine.Init())

	custom := configuration.NewInMemory()
	_, err := engine.Invoke(id, WithConfig(custom))
	require.NoError(t, err)
	assert.Same(t, custom, seen)
}

// Test_EngineImpl_Invoke_AppliesNetworkAccessSetup pins that Invoke decorates the
// per-invocation network stack after CreateNetworkAccess (outside the engine lock),
// which is how contributors and similar features activate without reading credentials in Init.
func Test_EngineImpl_Invoke_AppliesNetworkAccessSetup(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	setup, ok := engine.GetNetworkAccess().(networking.NetworkAccessSetup)
	require.True(t, ok)

	var applied atomic.Int32
	setup.AddSetupHook(func(_ networking.NetworkAccess, _ configuration.Configuration) {
		applied.Add(1)
	})

	id := NewWorkflowIdentifier("setup.invoke")
	_, err := engine.Register(id, ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError)),
		func(InvocationContext, []Data) ([]Data, error) { return nil, nil })
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	assert.Equal(t, int32(0), applied.Load(), "Init must not apply network setup hooks")

	_, err = engine.Invoke(id)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, applied.Load(), int32(1), "Invoke must apply setup hooks on the invocation network access")
}

// Test_EngineImpl_Invoke_WithConfigBindsPostInvokeHooks ensures hooks see the
// caller-supplied configuration rather than the engine's, so credential-bearing
// hook work does not fall back to the default profile's token.
func Test_EngineImpl_Invoke_WithConfigBindsPostInvokeHooks(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	engine.GetConfiguration().Set(configuration.AUTHENTICATION_TOKEN, "engine-token")
	id := NewWorkflowIdentifier("hook.config")
	_, err := engine.Register(id, ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError)),
		func(InvocationContext, []Data) ([]Data, error) { return nil, nil })
	require.NoError(t, err)

	var hookToken string
	require.NoError(t, AddPostInvokeHook(engine, func(_ context.Context, e Engine, _ InvokeOutput) {
		hookToken = e.GetConfiguration().GetString(configuration.AUTHENTICATION_TOKEN)
	}))
	require.NoError(t, engine.Init())

	custom := configuration.NewInMemory()
	custom.Set(configuration.AUTHENTICATION_TOKEN, "caller-token")
	_, err = engine.Invoke(id, WithConfig(custom))
	require.NoError(t, err)
	assert.Equal(t, "caller-token", hookToken)
}

func Test_EngineImpl_Invoke_StringPanicIsReraisedAsIs(t *testing.T) {
	engine, id := setupHookTestEngine(t, "panic.string", func(InvocationContext, []Data) ([]Data, error) {
		panic("callback blew up")
	})
	require.NoError(t, engine.Init())

	assert.PanicsWithValue(t, "callback blew up", func() {
		engine.Invoke(id) //nolint:errcheck // panic prevents return
	})
}

func Test_EngineImpl_Invoke_ErrorPanicIsWrappedForHooksAndReraisedAsIs(t *testing.T) {
	panicErr := errors.New("callback panicked with an error")
	engine, id := setupHookTestEngine(t, "panic.error", func(InvocationContext, []Data) ([]Data, error) {
		panic(panicErr)
	})

	var hookErr error
	require.NoError(t, AddPostInvokeHook(engine, func(_ context.Context, _ Engine, result InvokeOutput) {
		hookErr = result.GetError()
	}))
	require.NoError(t, engine.Init())

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		engine.Invoke(id) //nolint:errcheck // panic prevents return
	}()
	assert.Same(t, panicErr, recovered)
	assert.ErrorIs(t, hookErr, panicErr)
}
