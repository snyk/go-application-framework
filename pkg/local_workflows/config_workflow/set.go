package config_workflow

import (
	"strings"

	"github.com/snyk/error-catalog-golang-public/cli"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_CONFIG_SET workflow.Identifier = workflow.NewWorkflowIdentifier("config.set")

// configSetWorkflowEntryPoint stores each KEY=VALUE argument as a string. Nothing is written unless every argument is valid.
func configSetWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	args := config.GetStringSlice(argsAlias)
	if len(args) == 0 {
		return nil, nil
	}
	for _, arg := range args {
		if key, _, ok := strings.Cut(arg, "="); !ok || key == "" {
			return nil, cli.NewCommandArgsError("config:set requires arguments of the form KEY=VALUE")
		}
	}
	var out strings.Builder
	err := writeLocked(invocationCtx.Context(), config, func(storage *configuration.JsonStorage) error {
		for _, arg := range args {
			key, value, _ := strings.Cut(arg, "=")
			if err := storage.Set(key, value); err != nil {
				return err
			}
			out.WriteString(key + " updated\n")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return textOutput(WORKFLOWID_CONFIG_SET, out.String()), nil
}
