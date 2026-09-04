package localworkflows

import (
	contributors "github.com/snyk/go-application-framework/internal/contributors/hook"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow"
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
		doctor_workflow.InitDoctorWorkflow,
		contributors.Init,
	}

	for i := range initMethods {
		err = initMethods[i](engine)
		if err != nil {
			return err
		}
	}

	return err
}
