package config_workflow

import "github.com/snyk/go-application-framework/pkg/workflow"

// InitConfigWorkflows registers the config workflows with the engine.
func InitConfigWorkflows(engine workflow.Engine) error {
	return initEnvironmentWorkflow(engine)
}
