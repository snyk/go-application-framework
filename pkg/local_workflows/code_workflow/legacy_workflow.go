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

	// Preserve RAW_CMD_ARGS from the invocation when already set (e.g. by the ostest workflow).
	// Overwriting with os.Args[1:] is only correct when the current process is the CLI and
	// the user ran a top-level command. When invoked from ostest (CLI or snyk-ls), the test
	// workflow has already set the correct args; using os.Args[1:] would be wrong when the
	// process is snyk-ls (e.g. ["language-server", "-l", "info"]) and would cause legacycli
	// to fail with exit status 2.
	argsAlreadySet := len(config.GetStringSlice(configuration.RAW_CMD_ARGS)) > 0
	if !argsAlreadySet {
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	}
	// Single rule for all callers (ostest, code.test, etc.): when args were pre-set we are
	// invoked from code and want capture; when we set args from os.Args we are top-level CLI
	// and want stdio. Avoids relying on callers to set WORKFLOW_USE_STDIO and keeps code.test
	// and other EntryPointLegacy users consistent.
	config.Set(configuration.WORKFLOW_USE_STDIO, !argsAlreadySet)

	// run legacycli
	result, err = engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	return result, err
}
