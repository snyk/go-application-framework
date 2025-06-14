package workflow

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

func Test_EngineWrapper_Invoke(t *testing.T) {
	engine := NewWorkFlowEngine(configuration.NewWithOpts())
	test1Id := NewWorkflowIdentifier("test1")
	noOpWorkflowOptions := ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))
	input := []Data{NewData(NewTypeIdentifier(test1Id, "input"), "random", nil)}
	counter := 0

	wrapper := engineWrapper{
		WrappedEngine:                   engine,
		defaultInstrumentationCollector: analytics.NewInstrumentationCollector(),
	}

	_, err := wrapper.Register(test1Id, noOpWorkflowOptions, func(invocation InvocationContext, input []Data) ([]Data, error) {
		invocation.GetAnalytics().AddExtensionIntegerValue(fmt.Sprintf("%d", counter), counter)
		counter += 1
		return input, nil
	})
	assert.NoError(t, err)

	err = wrapper.Init()
	assert.NoError(t, err)

	output, err := wrapper.Invoke(test1Id)
	assert.NoError(t, err)
	assert.Empty(t, output)

	output, err = wrapper.InvokeWithInput(test1Id, input)
	assert.NoError(t, err)
	assert.Equal(t, input, output)

	output, err = wrapper.InvokeWithConfig(test1Id, configuration.NewWithOpts())
	assert.NoError(t, err)
	assert.Empty(t, output)

	output, err = wrapper.InvokeWithInputAndConfig(test1Id, input, configuration.NewWithOpts())
	assert.NoError(t, err)
	assert.Equal(t, input, output)

	assert.Equal(t, 4, counter)

	// ensure the provided collector has the expected data
	instrumentationData, err := analytics.GetV2InstrumentationObject(wrapper.defaultInstrumentationCollector)
	assert.NoError(t, err)
	assert.NotNil(t, instrumentationData)

	extension := *instrumentationData.Data.Attributes.Interaction.Extension
	for i := range counter {
		assert.Equal(t, float64(i), extension[fmt.Sprintf("test1::%d", i)])
	}
}

func Test_EngineWrapper_Accessors(t *testing.T) {
	test1Id := NewWorkflowIdentifier("test1")
	noOpWorkflowOptions := ConfigurationOptionsFromFlagset(pflag.NewFlagSet("", pflag.ContinueOnError))
	logger := zerolog.Nop()

	engine := NewWorkFlowEngine(configuration.NewWithOpts())
	wrapper := engineWrapper{
		WrappedEngine: engine,
	}

	_, err := wrapper.Register(test1Id, noOpWorkflowOptions, func(invocation InvocationContext, input []Data) ([]Data, error) { return nil, nil })
	assert.NoError(t, err)

	wrapper.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("myapp")))
	wrapper.SetConfiguration(configuration.NewWithOpts())
	wrapper.SetLogger(&logger)
	wrapper.SetUserInterface(nil)

	assert.Equal(t, engine.GetLogger(), wrapper.GetLogger())
	assert.Equal(t, engine.GetConfiguration(), wrapper.GetConfiguration())
	assert.Equal(t, engine.GetAnalytics(), wrapper.GetAnalytics())
	assert.Equal(t, engine.GetNetworkAccess(), wrapper.GetNetworkAccess())
	assert.Equal(t, engine.GetRuntimeInfo(), wrapper.GetRuntimeInfo())
	assert.Equal(t, engine.GetWorkflows(), wrapper.GetWorkflows())
	assert.Equal(t, engine.GetUserInterface(), wrapper.GetUserInterface())

	a, aOk := wrapper.GetWorkflow(test1Id)
	b, bOk := engine.GetWorkflow(test1Id)
	assert.Equal(t, aOk, bOk)
	assert.Equal(t, a, b)
}
