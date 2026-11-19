package config_workflow

import (
	"strings"

	"github.com/snyk/error-catalog-golang-public/cli"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_CONFIG_GET workflow.Identifier = workflow.NewWorkflowIdentifier("config.get")

// configGetWorkflowEntryPoint prints the stored value of a key. A non-empty SNYK_CFG_<KEY> variable wins over the file.
func configGetWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	args := config.GetStringSlice(argsAlias)
	if len(args) == 0 || args[0] == "" {
		return nil, cli.NewCommandArgsError("config:get requires an argument")
	}
	key := args[0]

	if value := config.GetString("snyk_cfg_" + strings.ReplaceAll(key, "-", "_")); value != "" {
		return textOutput(WORKFLOWID_CONFIG_GET, value), nil
	}
	values, err := readConfigFile(config)
	if err != nil {
		return nil, err
	}
	value, ok := values[key]
	if !ok {
		return nil, nil
	}
	return textOutput(WORKFLOWID_CONFIG_GET, displayValue(value)), nil
}
