package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initializes all local workflows
// localworkflows are initialized when create a new workflow engine via app.CreateAppEngine()
func Init(engine workflow.Engine) error {
	var err error

	initMethods := []func(workflow.Engine) error{
		InitDepGraphWorkflow,
		InitOutputWorkflow,
		InitWhoAmIWorkflow,
		// InitAuth, Use legacy CLI for authentication for now, until OAuth is ready
	}

	for i := range initMethods {
		err = initMethods[i](engine)
		if err != nil {
			return err
		}
	}

	return err
}
