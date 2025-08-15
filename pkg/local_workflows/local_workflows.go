package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initializes all local workflows
// localworkflows are initialized when create a new workflow engine via app.CreateAppEngine()
func Init(engine workflow.Engine) error {
	var err error

	initMethods := []func(workflow.Engine) error{
		InitOutputWorkflow,
		InitWhoAmIWorkflow,
		InitAuth,
		InitReportAnalyticsWorkflow,
		InitConfigWorkflow,
		InitDataTransformationWorkflow,
		InitFilterFindingsWorkflow,
		InitToolsWorkflowList,
		InitToolsWorkflowShow,
	}

	for i := range initMethods {
		err = initMethods[i](engine)
		if err != nil {
			return err
		}
	}

	return err
}
