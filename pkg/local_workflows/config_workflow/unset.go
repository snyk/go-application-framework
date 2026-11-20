package config_workflow

import (
	"github.com/snyk/error-catalog-golang-public/cli"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_CONFIG_UNSET workflow.Identifier = workflow.NewWorkflowIdentifier("config.unset")

// configUnsetWorkflowEntryPoint deletes the key given as the first argument, and reports it deleted even if it was not
// stored.
func configUnsetWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	args := config.GetStringSlice(argsAlias)
	if len(args) == 0 || args[0] == "" {
		return nil, cli.NewCommandArgsError("config:unset requires an argument")
	}
	err := writeLocked(invocationCtx.Context(), config, func(storage *configuration.JsonStorage) error {
		return storage.Set(args[0], configuration.KeyDeleted)
	})
	if err != nil {
		return nil, err
	}
	return textOutput(WORKFLOWID_CONFIG_UNSET, args[0]+" deleted"), nil
}
