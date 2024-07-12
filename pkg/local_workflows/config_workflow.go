package localworkflows

import (
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	configEnvWorkflowName = "config.environment"
)

var WORKFLOWID_CONFIG_ENVIRONMENT workflow.Identifier = workflow.NewWorkflowIdentifier(configEnvWorkflowName)

func InitConfigWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := pflag.NewFlagSet(codeWorkflowName, pflag.ExitOnError)
	_, err := engine.Register(WORKFLOWID_CONFIG_ENVIRONMENT, workflow.ConfigurationOptionsFromFlagset(flags), configEnvironmentWorkflowEntryPoint)
	return err
}

func configEnvironmentWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	//config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	logger.Debug().Msg("config environment workflow start")

	return result, err
}
