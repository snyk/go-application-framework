package instrumentation

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_DetermineStage(t *testing.T) {
	t.Run("returns dev by default", func(t *testing.T) {
		assert.Equal(t, "dev", DetermineStage(false))
	})

	t.Run("returns cicd for matching environments", func(t *testing.T) {
		t.Setenv("CI", "true")
		assert.Equal(t, "cicd", DetermineStage(true))
	})
}

func Test_GetKnownCommandsAndFlags(t *testing.T) {
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	actualCommands, actualFlags := GetKnownCommandsAndFlags(engine)
	assert.Equal(t, KNOWN_COMMANDS, actualCommands)
	assert.Equal(t, KNOWN_FLAGS, actualFlags)
}

func Test_GetKnownCommandsAndFlags_Extension(t *testing.T) {
	command1 := "awesome"
	command2 := "power"
	expectedCommands := append(KNOWN_COMMANDS, command1)
	expectedCommands = append(expectedCommands, command2)

	expectedFlags := append(KNOWN_FLAGS, "ever")
	expectedFlags = append(expectedFlags, "forever")

	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	flags.Bool("forever", true, "make awesomeness sticky")
	flags.Bool("ever", true, "make awesomeness sticky")

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)

	entry, err := engine.Register(workflow.NewWorkflowIdentifier(command1), workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	assert.NotNil(t, entry)
	assert.NoError(t, err)

	entry, err = engine.Register(workflow.NewWorkflowIdentifier(command2), workflow.ConfigurationOptionsFromFlagset(flags), func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		return nil, nil
	})
	assert.NotNil(t, entry)
	assert.NoError(t, err)

	actualCommands, actualFlags := GetKnownCommandsAndFlags(engine)
	assert.Equal(t, expectedCommands, actualCommands)
	assert.Equal(t, expectedFlags, actualFlags)
}
