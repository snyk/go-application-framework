package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
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
