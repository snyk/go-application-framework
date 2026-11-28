package config_workflow

import (
	"errors"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// InitConfigWorkflows registers the config workflows with the engine.
func InitConfigWorkflows(engine workflow.Engine) error {
	engine.GetConfiguration().AddAlternativeKeys(argsAlias, []string{configuration.INPUT_DIRECTORY})
	return errors.Join(
		initEnvironmentWorkflow(engine),
		register(engine, WORKFLOWID_CONFIG, configWorkflowEntryPoint),
		register(engine, WORKFLOWID_CONFIG_GET, configGetWorkflowEntryPoint),
	)
}

func register(engine workflow.Engine, id workflow.Identifier, callback workflow.Callback) error {
	_, err := engine.Register(id, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet(id.Host, pflag.ContinueOnError)), callback)
	return err
}
