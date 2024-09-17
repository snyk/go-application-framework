package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	transformWorkflowName = "transform"
)

var WORKFLOWID_TRANSFORM workflow.Identifier = workflow.NewWorkflowIdentifier(transformWorkflowName)

func InitTransformWorkflow(engine workflow.Engine) error {
	// initialize workflow configuration
	transformConfig := pflag.NewFlagSet(transformWorkflowName, pflag.ExitOnError)
	// add experimental flag to configuration
	transformConfig.Bool(experimentalFlag, false, "enable experimental transformer command")
	// add json flag to configuration
	transformConfig.Bool(jsonFlag, false, "output in json format")

	_, err := engine.Register(WORKFLOWID_TRANSFORM, workflow.ConfigurationOptionsFromFlagset(transformConfig), transformWorkflow)
	return err
}

func transformWorkflow(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	localFindings := local_models.LocalFinding{}

	output = []workflow.Data{
		workflow.NewData(
			"localfindings",
			"application/json", localFindings),
	}
	return nil, nil
}
