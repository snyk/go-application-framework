package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Init(engine workflow.Engine) error {
	var err error

	initMethods := []func(workflow.Engine) error{
		InitDepGraphWorkflow,
		InitOutputWorkflow,
		//sbom.Init,
	}

	for i := range initMethods {
		err = initMethods[i](engine)
		if err != nil {
			return err
		}
	}

	return err
}
