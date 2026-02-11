package code_workflow

import (
	"os"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func EntryPointLegacy(invocationCtx workflow.InvocationContext) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	engine := invocationCtx.GetEngine()

	config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	config.Set(configuration.WORKFLOW_USE_STDIO, true)

	// run legacycli
	result, err = engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	return result, err
}
