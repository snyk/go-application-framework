package workflow

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

var expectedDataIdentifier []Identifier

func callback1(invocation InvocationContext, input []Data) ([]Data, error) {
	if len(input) <= 0 {
		return nil, fmt.Errorf("Empty input data!")
	}

	typeId := NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl1data")
	d := NewDataFromInput(input[0], typeId, "application/json", nil)
	expectedDataIdentifier[0] = d.GetIdentifier()
	invocation.GetLogger().Println("callback1", d)
	return []Data{d}, nil
}

// create test workflow 2
func callback2(invocation InvocationContext, input []Data) ([]Data, error) {
	typeId := NewTypeIdentifier(invocation.GetWorkflowIdentifier(), "wfl2data")
	d := NewData(typeId, "application/json", nil)
	expectedDataIdentifier[1] = d.GetIdentifier()
	invocation.GetLogger().Println("callback2", d)
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
