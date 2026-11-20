package config_workflow

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_CONFIG_CLEAR workflow.Identifier = workflow.NewWorkflowIdentifier("config.clear")

// configClearWorkflowEntryPoint deletes every stored key. A file of invalid JSON is emptied too.
func configClearWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	err := writeLocked(invocationCtx.Context(), invocationCtx.GetConfiguration(), (*configuration.JsonStorage).Clear)
	if err != nil {
		return nil, err
	}
	return textOutput(WORKFLOWID_CONFIG_CLEAR, "config cleared"), nil
}
