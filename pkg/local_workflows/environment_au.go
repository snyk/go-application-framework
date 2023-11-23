package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var (
	WORKFLOWID_ENVIRONMENT_AU workflow.Identifier = workflow.NewWorkflowIdentifier(auEnvironmentWorkflowName)
)

const (
	auEnvironmentWorkflowName = "environment.au"
)

func InitAuEnvironmentWorkflow(engine workflow.Engine) error {
	// initialise workflow configuration
	params := pflag.NewFlagSet(auEnvironmentWorkflowName, pflag.ExitOnError)

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_ENVIRONMENT_AU, params, auEnvironmentEntrypoint)

	return err
}

// euEnvironmentEntrypoint is the entry point
func auEnvironmentEntrypoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	logger.Println(euEnvironmentWorkflowName + " workflow start")
	key := "endpoint"

	config.PersistInStorage(key)
	config.Set(key, "https://app.au.snyk.io/api")

	logger.Println(euEnvironmentWorkflowName + " workflow end")
	return nil, nil
}
