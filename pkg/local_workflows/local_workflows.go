package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initializes all local workflows
func Init(engine workflow.Engine) error {
	var err error

	initMethods := []func(workflow.Engine) error{
		InitDepGraphWorkflow,
		InitOutputWorkflow,
	}

	for i := range initMethods {
		err = initMethods[i](engine)
		if err != nil {
			return err
		}
	}

	return err
}
