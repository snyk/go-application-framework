package workflow

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

var expectedDataIdentifier []Identifier

func addPostInvokeHook(t *testing.T, e Engine, hook PostInvokeHook) {
	t.Helper()
	err := AddPostInvokeHook(e, hook)
	assert.NoError(t, err)
}

func setupHookTestEngine(t *testing.T, name string, callback Callback) (Engine, Identifier) {
	t.Helper()
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	wfId := NewWorkflowIdentifier(name)
	if callback == nil {
		callback = func(InvocationContext, []Data) ([]Data, error) { return nil, nil }
	}
	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError)), callback)
	assert.NoError(t, err)
	return engine, wfId
}

func callback1(invocation InvocationContext, input []Data) ([]Data, error) {
	if len(input) <= 0 {
		return nil, fmt.Errorf("Empty input data!")
	}

	typeId := NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
	d := NewDataFromInput(input[0], typeId, "application/json", nil)
	expectedDataIdentifier[0] = d.GetIdentifier()
	invocation.GetLogger().Println("callback1", d)
	invocation.GetAnalytics().AddExtensionStringValue("hello", "callback1")
	return []Data{d}, nil
}

// create test workflow 2
func callback2(invocation InvocationContext, input []Data) ([]Data, error) {
	typeId := NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl2data")
	d := NewData(typeId, "application/json", nil)
	expectedDataIdentifier[1] = d.GetIdentifier()
	invocation.GetLogger().Println("callback2", d)
	invocation.GetAnalytics().AddExtensionStringValue("hello", "callback2")
	return []Data{d}, nil
}

func callback3(invocation InvocationContext, input []Data) ([]Data, error) {
	return nil, fmt.Errorf("Something went wrong")
}

func Test_EngineBasics(t *testing.T) {
	config := configuration.New()
	config.Set(configuration.DEBUG, true)
	engine := NewWorkFlowEngine(config)
	expectedWorkflowCount := 0
	expectedDataIdentifier = make([]Identifier, 2)

	workflowId1 := NewWorkflowIdentifier("cmd1")
	workflowId2 := NewWorkflowIdentifier("cmd2")
	workflowId3 := NewWorkflowIdentifier("cmd3")

	// create test workflow 1
	flagset1 := pflag.NewFlagSet("1", pflag.ExitOnError)
	entry1, err := engine.Register(workflowId1, ConfigurationOptionsFromFlagset(flagset1), callback1)
	expectedWorkflowCount++
	assert.Nil(t, err)
	assert.NotNil(t, entry1)

	// create test workflow 2
	flagset2 := pflag.NewFlagSet("2", pflag.ExitOnError)
	entry2, err := engine.Register(workflowId2, ConfigurationOptionsFromFlagset(flagset2), callback2)
	expectedWorkflowCount++
	assert.Nil(t, err)
	assert.NotNil(t, entry2)

	// create test workflow 3
	flagset3 := pflag.NewFlagSet("3", pflag.ExitOnError)
	entry3, err := engine.Register(workflowId3, ConfigurationOptionsFromFlagset(flagset3), callback3)
	expectedWorkflowCount++
	assert.Nil(t, err)
	assert.NotNil(t, entry3)

	// method under test: GetWorkflows()
	workflowIds := engine.GetWorkflows()
	assert.Equal(t, expectedWorkflowCount, len(workflowIds))

	assert.Nil(t, engine.GetAnalytics())

	// method under test: Init()
	err = engine.Init()
	assert.Nil(t, err)

	assert.NotNil(t, engine.GetAnalytics())

	// method under test: Invoke()
	copyOfId := *workflowId2
	actualData1, err := engine.Invoke(&copyOfId)
	assert.Nil(t, err)
	assert.NotNil(t, actualData1)
	assert.NotNil(t, actualData1[0])
	assert.Equal(t, expectedDataIdentifier[1], actualData1[0].GetIdentifier())

	// method under test: Invoke()
	actualData2, err := engine.InvokeWithInput(workflowId1, actualData1)
	assert.Nil(t, err)
	assert.NotNil(t, actualData2)
	assert.NotNil(t, actualData2[0])
	assert.Equal(t, expectedDataIdentifier[0], actualData2[0].GetIdentifier())
	assert.NotEqual(t, expectedDataIdentifier[0], expectedDataIdentifier[1])
	assert.Equal(t, expectedDataIdentifier[0].Fragment, expectedDataIdentifier[1].Fragment)

	// method under test: Invoke() a workflow that always returns an error
	actualData3, err := engine.Invoke(workflowId3)
	assert.NotNil(t, err)
	assert.Nil(t, actualData3)
	fmt.Printf("%#v\n", err)

	// method under test: Invoke() with a non-exitsing id
	actualData4, err := engine.Invoke(NewWorkflowIdentifier("not existing"))
	assert.NotNil(t, err)
	assert.Nil(t, actualData4)
	fmt.Printf("%#v\n", err)

	obj, err := analytics.GetV2InstrumentationObject(engine.GetAnalytics().GetInstrumentation())
	assert.NoError(t, err)
	assert.NotNil(t, obj)

	extension := *obj.Data.Attributes.Interaction.Extension
	assert.Equal(t, "callback1", extension["cmd1::hello"])
	assert.Equal(t, "callback2", extension["cmd2::hello"])
}

func Test_EngineBasics_InvokeWithCollector(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewWithOpts())
	collector := analytics.NewInstrumentationCollector()

	expectedKey := "some"
	expectedValue := "value"

	test1Id := NewWorkflowIdentifier("test1")
	test2Id := NewWorkflowIdentifier("test2")
	noOpWorkflowOptions := ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))
	input := []Data{NewData(NewTypeIdentifier(test1Id, "input"), "random", nil)}

	_, err := engine.Register(test1Id, noOpWorkflowOptions, func(invocation InvocationContext, input []Data) ([]Data, error) {
		invocation.GetAnalytics().AddExtensionStringValue(expectedKey, expectedValue)
		return invocation.GetEngine().Invoke(test2Id, WithInput(input)) // without specifying the collector, Invoke will use the default
	})
	assert.NoError(t, err)

	_, err = engine.Register(test2Id, noOpWorkflowOptions, func(invocation InvocationContext, input []Data) ([]Data, error) {
		invocation.GetAnalytics().AddExtensionStringValue(expectedKey, expectedValue)
		return input, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	testcases := []struct {
		name            string
		invokeOptions   []EngineInvokeOption
		assertCollector analytics.InstrumentationCollector
	}{
		{
			name:            "Use specified Instrumentation Collector",
			assertCollector: collector,
			invokeOptions:   []EngineInvokeOption{WithInput(input), WithInstrumentationCollector(collector)},
		},
		{
			name:            "Use default Instrumentation Collector",
			assertCollector: engine.GetAnalytics().GetInstrumentation(),
			invokeOptions:   []EngineInvokeOption{WithInput(input)},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// invoke method under test, case collector is specified
			output, err := engine.Invoke(test1Id, tc.invokeOptions...)
			assert.NoError(t, err)
			assert.Equal(t, input, output)

			// ensure the provided collector has the expected data
			instrumentationData, err := analytics.GetV2InstrumentationObject(tc.assertCollector)
			assert.NoError(t, err)
			assert.NotNil(t, instrumentationData)

			extension := *instrumentationData.Data.Attributes.Interaction.Extension
			assert.Equal(t, expectedValue, extension["test1::some"])
			assert.Equal(t, expectedValue, extension["test2::some"])
		})
	}
}

func Test_EngineRegisterErrorHandling(t *testing.T) {
	configuration := configuration.New()
	engine := NewWorkFlowEngine(configuration)

	flagset := pflag.NewFlagSet("1", pflag.ExitOnError)
	callback := func(invocation InvocationContext, input []Data) ([]Data, error) {
		return nil, nil
	}

	entry, err := engine.Register(nil, ConfigurationOptionsFromFlagset(flagset), callback)
	assert.NotNil(t, err)
	assert.Nil(t, entry)

	entry, err = engine.Register(&url.URL{}, nil, callback)
	assert.NotNil(t, err)
	assert.Nil(t, entry)

	entry, err = engine.Register(&url.URL{}, ConfigurationOptionsFromFlagset(flagset), nil)
	assert.NotNil(t, err)
	assert.Nil(t, entry)
}

func Test_Engine_SetterGlobalValues(t *testing.T) {
	config := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
	config2 := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
	logger2 := &zerolog.Logger{}

	engine := NewWorkFlowEngine(config)

	err := engine.Init()
	logger := engine.GetLogger()
	assert.Nil(t, err)

	engine.SetConfiguration(config2)
	assert.Equal(t, config2, engine.GetConfiguration())
	assert.Equal(t, config2, engine.GetNetworkAccess().GetConfiguration())
	assert.NotEqual(t, config, engine.GetConfiguration())

	engine.SetLogger(logger2)
	assert.Equal(t, logger2, engine.GetLogger())
	assert.Equal(t, logger2, engine.GetNetworkAccess().GetLogger())
	assert.NotEqual(t, logger, engine.GetLogger())
}

func Test_Engine_SetterRuntimeInfo(t *testing.T) {
	ri := runtimeinfo.New()
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	engine.SetRuntimeInfo(ri)

	assert.Equal(t, ri, engine.GetRuntimeInfo())
}

func Test_Engine_ClonedNetworkAccess(t *testing.T) {
	valueName := "randomValue"
	expected := 815
	config := configuration.NewInMemory()
	config.Set(valueName, expected)

	engine := NewWorkFlowEngine(config)

	workflowId := NewWorkflowIdentifier("cmd")
	_, err := engine.Register(workflowId, ConfigurationOptionsFromFlagset(pflag.NewFlagSet("1", pflag.ExitOnError)), func(invocation InvocationContext, input []Data) ([]Data, error) {
		assert.Equal(t, expected, invocation.GetNetworkAccess().GetConfiguration().GetInt(valueName))
		assert.Equal(t, expected, invocation.GetConfiguration().GetInt(valueName))

		newValue := 1

		// changing the network configuration inside a callback
		invocation.GetNetworkAccess().GetConfiguration().Set(valueName, newValue)

		assert.Equal(t, newValue, invocation.GetNetworkAccess().GetConfiguration().GetInt(valueName))
		assert.Equal(t, newValue, invocation.GetConfiguration().GetInt(valueName))
		return []Data{}, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	_, err = engine.Invoke(workflowId)
	assert.NoError(t, err)

	// ensure that the config value in the original config wasn't changed
	actual := config.GetInt(valueName)
	assert.Equal(t, expected, actual)
}

func Test_GetCommandFromWorkflowIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		id       Identifier
		expected string
	}{
		{"valid workflow id", NewWorkflowIdentifier("snyk test"), "snyk test"},
		{"single word", NewWorkflowIdentifier("analyze"), "analyze"},
		{"nil id", nil, ""},
		{"non-flw scheme", &url.URL{Scheme: "http", Host: "example"}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetCommandFromWorkflowIdentifier(tc.id))
		})
	}
}

func Test_GetGlobalConfiguration(t *testing.T) {
	opts := GetGlobalConfiguration()
	assert.NotNil(t, opts)

	fs := FlagsetFromConfigurationOptions(opts)
	assert.NotNil(t, fs)
	assert.NotNil(t, fs.Lookup(configuration.ORGANIZATION))
	assert.NotNil(t, fs.Lookup(configuration.DEBUG))
	assert.NotNil(t, fs.Lookup(configuration.INSECURE_HTTPS))
}

func Test_EngineImpl_InvokeWithConfig(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("cfgtest")
	flagset := pflag.NewFlagSet("cfg", pflag.ContinueOnError)
	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		return nil, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	output, err := engine.Invoke(wfId, WithConfig(configuration.NewInMemory()))
	assert.NoError(t, err)
	assert.Nil(t, output)
}

func Test_EngineImpl_InvokeWithInputAndConfig(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("iactest")
	flagset := pflag.NewFlagSet("iac", pflag.ContinueOnError)
	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		return input, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	inputData := []Data{NewData(NewTypeIdentifier(wfId, "d"), "text/plain", nil)}
	output, err := engine.Invoke(wfId, WithInput(inputData), WithConfig(configuration.NewInMemory()))
	assert.NoError(t, err)
	assert.Equal(t, inputData, output)
}

func Test_EngineImpl_AddExtensionInitializer(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	initCalled := false
	engine.AddExtensionInitializer(func(e Engine) error {
		initCalled = true
		return nil
	})

	err := engine.Init()
	assert.NoError(t, err)
	assert.True(t, initCalled)
}

func Test_EngineImpl_AddExtensionInitializer_Error(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	engine.AddExtensionInitializer(func(e Engine) error {
		return fmt.Errorf("init failed")
	})

	err := engine.Init()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "init failed")
}

func Test_EngineImpl_InvokeBeforeInit(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("noinit")
	flagset := pflag.NewFlagSet("ni", pflag.ContinueOnError)
	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		return nil, nil
	})
	assert.NoError(t, err)

	_, err = engine.Invoke(wfId)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initialized")
}

func Test_EntryImpl_Methods(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("entrytest")
	flagset := pflag.NewFlagSet("e", pflag.ContinueOnError)
	cfgOpts := ConfigurationOptionsFromFlagset(flagset)

	entry, err := engine.Register(wfId, cfgOpts, func(invocation InvocationContext, input []Data) ([]Data, error) {
		return nil, nil
	})
	assert.NoError(t, err)

	// GetConfigurationOptions
	assert.Equal(t, cfgOpts, entry.GetConfigurationOptions())

	// IsVisible (default true)
	assert.True(t, entry.IsVisible())

	// SetVisibility
	entry.SetVisibility(false)
	assert.False(t, entry.IsVisible())

	entry.SetVisibility(true)
	assert.True(t, entry.IsVisible())

	// GetEntryPoint
	assert.NotNil(t, entry.GetEntryPoint())
}

func Test_InvocationContext_AllMethods(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("ictxtest")
	flagset := pflag.NewFlagSet("ic", pflag.ContinueOnError)

	ri := runtimeinfo.New(runtimeinfo.WithName("test-app"))
	engine.SetRuntimeInfo(ri)

	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		// Context
		ctx := invocation.Context()
		assert.NotNil(t, ctx)

		// GetEnhancedLogger
		assert.NotNil(t, invocation.GetEnhancedLogger())

		// GetUserInterface
		assert.NotNil(t, invocation.GetUserInterface())

		// GetRuntimeInfo
		assert.Equal(t, ri, invocation.GetRuntimeInfo())

		// GetWorkflowIdentifier
		assert.Equal(t, wfId.String(), invocation.GetWorkflowIdentifier().String())

		// GetConfiguration
		assert.NotNil(t, invocation.GetConfiguration())

		// GetEngine
		assert.NotNil(t, invocation.GetEngine())

		// GetAnalytics
		assert.NotNil(t, invocation.GetAnalytics())

		// GetNetworkAccess
		assert.NotNil(t, invocation.GetNetworkAccess())

		return nil, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	_, err = engine.Invoke(wfId)
	assert.NoError(t, err)
}

func Test_EngineWrapper_AddExtensionInitializer(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewWithOpts())
	wrapper := &engineWrapper{WrappedEngine: engine}

	initCalled := false
	wrapper.AddExtensionInitializer(func(e Engine) error {
		initCalled = true
		return nil
	})

	err := wrapper.Init()
	assert.NoError(t, err)
	assert.True(t, initCalled)
}

func Test_EngineInvocationConcurrent(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	flagset := pflag.NewFlagSet("1", pflag.ExitOnError)
	callback := func(invocation InvocationContext, input []Data) ([]Data, error) {
		return nil, nil
	}

	workflowId := NewWorkflowIdentifier("test")
	_, err := engine.Register(workflowId, ConfigurationOptionsFromFlagset(flagset), callback)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	N := 10
	stop := make(chan struct{}, N)
	for range N {
		go func() {
			logger := zerolog.Nop()
			engine.SetLogger(&logger)
			engine.SetConfiguration(configuration.NewWithOpts())
			_, invokeErr := engine.Invoke(workflowId)
			assert.NoError(t, invokeErr)
			stop <- struct{}{}
		}()
	}

	for range N {
		select {
		case <-stop:
		case <-time.After(time.Second):
			assert.FailNow(t, "timeout reached")
			return
		}
	}
}

func Test_EngineImpl_InvokeWithContext_CustomContext(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("ctxtest")
	wfIdNested := NewWorkflowIdentifier("ctxtest-nested")
	flagset := pflag.NewFlagSet("ctx", pflag.ContinueOnError)

	var receivedCtx context.Context
	// register entry workflow
	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		output, localError := invocation.GetEngine().Invoke(wfIdNested)
		receivedCtx = invocation.Context()
		return output, localError
	})
	assert.NoError(t, err)

	var receivedCtxNested context.Context
	// register nested workflow
	_, err = engine.Register(wfIdNested, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		receivedCtxNested = invocation.Context()
		return nil, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	// Create a context with a specific value and deadline to verify it's passed through
	type ctxKey string
	testKey := ctxKey("test-key")
	testValue := "test-value"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, testKey, testValue)

	_, err = engine.Invoke(wfId, WithContext(ctx))
	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx)
	assert.Equal(t, testValue, receivedCtx.Value(testKey))

	assert.NotNil(t, receivedCtxNested)
	assert.Equal(t, testValue, receivedCtxNested.Value(testKey))

	// Verify deadline is propagated
	deadline, hasDeadline := receivedCtxNested.Deadline()
	assert.True(t, hasDeadline, "context should have a deadline")
	assert.False(t, deadline.IsZero(), "deadline should not be zero")
}

func Test_EngineImpl_InvokeWithContext_DefaultContext(t *testing.T) {
	config := configuration.NewInMemory()
	engine := NewWorkFlowEngine(config)

	wfId := NewWorkflowIdentifier("ctxdefault")
	flagset := pflag.NewFlagSet("cd", pflag.ContinueOnError)

	var receivedCtx context.Context
	_, err := engine.Register(wfId, ConfigurationOptionsFromFlagset(flagset), func(invocation InvocationContext, input []Data) ([]Data, error) {
		receivedCtx = invocation.Context()
		return nil, nil
	})
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	// Invoke without WithContext - should get a non-nil default context
	_, err = engine.Invoke(wfId)
	assert.NoError(t, err)
	assert.NotNil(t, receivedCtx)
}

func Test_PostInvokeHook_FiresOnTopLevel(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "hook-test", nil)

	var hookCalled bool
	var receivedHctx PostInvokeContext
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		hookCalled = true
		receivedHctx = hctx
	})

	assert.NoError(t, engine.Init())
	_, err := engine.Invoke(wfId)
	assert.NoError(t, err)

	assert.True(t, hookCalled)
	assert.Equal(t, wfId.String(), receivedHctx.GetWorkflowIdentifier().String())
	assert.NoError(t, receivedHctx.GetError())
}

func Test_PostInvokeHook_ReceivesError(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "hook-err", func(InvocationContext, []Data) ([]Data, error) {
		return nil, fmt.Errorf("workflow failed")
	})

	var receivedErr error
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		receivedErr = hctx.GetError()
	})

	assert.NoError(t, engine.Init())
	_, err := engine.Invoke(wfId)
	assert.Error(t, err)
	assert.EqualError(t, receivedErr, "workflow failed")
}

func Test_PostInvokeHook_SkippedForNestedInvocations(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	innerWfId := NewWorkflowIdentifier("inner")
	outerWfId := NewWorkflowIdentifier("outer")
	opts := ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))

	_, err := engine.Register(innerWfId, opts, func(InvocationContext, []Data) ([]Data, error) { return nil, nil })
	assert.NoError(t, err)
	_, err = engine.Register(outerWfId, opts, func(inv InvocationContext, _ []Data) ([]Data, error) {
		return inv.GetEngine().Invoke(innerWfId)
	})
	assert.NoError(t, err)

	hookCallCount := 0
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		hookCallCount++
	})

	assert.NoError(t, engine.Init())
	_, err = engine.Invoke(outerWfId)
	assert.NoError(t, err)
	assert.Equal(t, 1, hookCallCount, "hook should fire exactly once for the top-level invocation")
}

func Test_PostInvokeHook_MultipleHooksAllFire(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "multi-hook", nil)

	var mu sync.Mutex
	var fired []int
	for _, id := range []int{1, 2, 3} {
		addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
			mu.Lock()
			fired = append(fired, id)
			mu.Unlock()
		})
	}

	assert.NoError(t, engine.Init())
	_, err := engine.Invoke(wfId)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []int{1, 2, 3}, fired)
}

func Test_PostInvokeHook_ConcurrentTopLevelInvocations(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "concurrent-hook", nil)

	var mu sync.Mutex
	hookCallCount := 0
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		mu.Lock()
		hookCallCount++
		mu.Unlock()
	})

	assert.NoError(t, engine.Init())

	N := 10
	done := make(chan struct{}, N)
	for range N {
		go func() {
			_, invokeErr := engine.Invoke(wfId)
			assert.NoError(t, invokeErr)
			done <- struct{}{}
		}()
	}
	for range N {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			assert.FailNow(t, "timeout")
			return
		}
	}
	assert.Equal(t, N, hookCallCount)
}

func Test_PostInvokeHook_FiresForMissingWorkflow(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewInMemory())
	missingWfId := NewWorkflowIdentifier("does-not-exist")

	var receivedHctx PostInvokeContext
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		receivedHctx = hctx
	})

	assert.NoError(t, engine.Init())
	_, err := engine.Invoke(missingWfId)
	assert.Error(t, err)
	assert.Equal(t, missingWfId.String(), receivedHctx.GetWorkflowIdentifier().String())
	assert.Error(t, receivedHctx.GetError())
}

func Test_PostInvokeHook_IgnoredAfterInit(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "late-hook", nil)
	assert.NoError(t, engine.Init())

	hookCalled := false
	assert.Error(t, AddPostInvokeHook(engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		hookCalled = true
	}))

	_, err := engine.Invoke(wfId)
	assert.NoError(t, err)
	assert.False(t, hookCalled)
}

func Test_PostInvokeHook_NilHookIgnored(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "nil-hook", nil)
	addPostInvokeHook(t, engine, nil)
	assert.NoError(t, engine.Init())

	assert.NotPanics(t, func() {
		_, err := engine.Invoke(wfId)
		assert.NoError(t, err)
	})
}

func Test_PostInvokeHook_PanicRecovery(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "panic-hook", nil)

	var mu sync.Mutex
	var fired []int
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		mu.Lock()
		fired = append(fired, 1)
		mu.Unlock()
	})
	addPostInvokeHook(t, engine, func(context.Context, Engine, PostInvokeContext) { panic("hook blew up") })
	addPostInvokeHook(t, engine, func(ctx context.Context, eng Engine, hctx PostInvokeContext) {
		mu.Lock()
		fired = append(fired, 3)
		mu.Unlock()
	})

	assert.NoError(t, engine.Init())
	assert.NotPanics(t, func() {
		_, err := engine.Invoke(wfId)
		assert.NoError(t, err)
	})
	assert.ElementsMatch(t, []int{1, 3}, fired, "hooks before and after the panicking hook should still fire")
}

func Test_PostInvokeHook_FiresPerInvocation(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "per-invoke", nil)

	hookCallCount := 0
	addPostInvokeHook(t, engine, func(context.Context, Engine, PostInvokeContext) { hookCallCount++ })

	assert.NoError(t, engine.Init())
	for range 3 {
		_, err := engine.Invoke(wfId)
		assert.NoError(t, err)
	}
	assert.Equal(t, 3, hookCallCount)
}

func Test_PostInvokeHook_ReceivesContextValues(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "ctx-hook", nil)

	type ctxKey string
	testKey := ctxKey("hook-test-key")

	var receivedCtx context.Context
	addPostInvokeHook(t, engine, func(ctx context.Context, _ Engine, _ PostInvokeContext) { receivedCtx = ctx })

	assert.NoError(t, engine.Init())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, testKey, "hook-test-value")

	_, err := engine.Invoke(wfId, WithContext(ctx))
	assert.NoError(t, err)
	assert.Equal(t, "hook-test-value", receivedCtx.Value(testKey))

	deadline, hasDeadline := receivedCtx.Deadline()
	assert.True(t, hasDeadline)
	assert.False(t, deadline.IsZero())
}

func Test_PostInvokeHook_NestedInvokeOfMissingWorkflow(t *testing.T) {
	engine, outerWfId := setupHookTestEngine(t, "outer-missing-inner", func(inv InvocationContext, _ []Data) ([]Data, error) {
		_, err := inv.GetEngine().Invoke(NewWorkflowIdentifier("nonexistent"))
		return nil, err
	})

	hookCallCount := 0
	addPostInvokeHook(t, engine, func(context.Context, Engine, PostInvokeContext) { hookCallCount++ })

	assert.NoError(t, engine.Init())
	_, err := engine.Invoke(outerWfId)
	assert.Error(t, err)
	assert.Equal(t, 1, hookCallCount, "hook fires once for the top-level invocation only")
}

func Test_PostInvokeHook_FiresOnCallbackPanic(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "panic-callback", func(InvocationContext, []Data) ([]Data, error) {
		panic("callback blew up")
	})

	var hookErr error
	hookCalled := false
	addPostInvokeHook(t, engine, func(_ context.Context, _ Engine, hctx PostInvokeContext) {
		hookCalled = true
		hookErr = hctx.GetError()
	})

	assert.NoError(t, engine.Init())
	assert.Panics(t, func() {
		engine.Invoke(wfId) //nolint:errcheck // panic prevents return
	})
	assert.True(t, hookCalled, "hook must fire even when the callback panics")
	assert.ErrorContains(t, hookErr, "callback blew up")
}

func Test_PostInvokeHook_PanicNilObserved(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "panic-nil", func(InvocationContext, []Data) ([]Data, error) {
		panic(any(nil)) //nolint:govet // intentional: verifying Go 1.21+ PanicNilError is observed by hooks
	})

	var hookErr error
	addPostInvokeHook(t, engine, func(_ context.Context, _ Engine, hctx PostInvokeContext) {
		hookErr = hctx.GetError()
	})

	assert.NoError(t, engine.Init())
	assert.Panics(t, func() {
		engine.Invoke(wfId) //nolint:errcheck // panic prevents return
	})
	assert.NotNil(t, hookErr, "hook should observe error from panic(nil) via Go 1.21+ PanicNilError")
}

func Test_PostInvokeHook_Timeout(t *testing.T) {
	engine, wfId := setupHookTestEngine(t, "timeout-test", nil)
	impl := engine.(*EngineImpl)
	impl.postInvokeHookTimer = 50 * time.Millisecond

	var secondHookDone sync.WaitGroup
	secondHookDone.Add(1)
	addPostInvokeHook(t, engine, func(ctx context.Context, _ Engine, _ PostInvokeContext) {
		<-ctx.Done()
		time.Sleep(time.Second)
	})
	addPostInvokeHook(t, engine, func(context.Context, Engine, PostInvokeContext) { secondHookDone.Done() })

	assert.NoError(t, engine.Init())

	start := time.Now()
	_, err := engine.Invoke(wfId)
	secondHookDone.Wait()
	assert.NoError(t, err)
	assert.Less(t, time.Since(start), 2*time.Second, "invoke should not block on the hanging hook")
}
