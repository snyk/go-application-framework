package workflow

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
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

// ensure that analytics header don't include the authorization token, as the end-point doesn't handle it
func Test_EngineAnalyticsInitialization(t *testing.T) {
	config := configuration.New()
	config.Set(configuration.API_URL, constants.SNYK_DEFAULT_API_URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, "1234567890")

	engine := NewWorkFlowEngine(config)
	engine.Init()
	analytics := engine.GetAnalytics()
	networkAccess := engine.GetNetworkAccess()

	url := analytics.GetUrl()
	actualAnalyticsHeader := networkAccess.GetDefaultHeader(url)

	_, ok := actualAnalyticsHeader[networking.HEADER_FIELD_AUTHORIZATION]
	assert.False(t, ok)
}
