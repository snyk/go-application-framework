package app

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func CreateAppEngine() workflow.Engine {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	engine.AddExtensionInitializer(localworkflows.Init)

	return engine
}
