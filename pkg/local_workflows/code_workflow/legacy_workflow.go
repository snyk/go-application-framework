package code_workflow

import (
	"os"
	"slices"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	codeWorkflowExperimentalFlag = configuration.FLAG_EXPERIMENTAL
)

func EntryPointLegacy(invocationCtx workflow.InvocationContext) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	engine := invocationCtx.GetEngine()

	useExperimentalOutput := config.GetBool(codeWorkflowExperimentalFlag) && !slices.Contains(os.Args, "--report")
	if useExperimentalOutput {
		args := []string{"--json"}

		// Add the rest of the arguments
		for _, arg := range os.Args[1:] {
			if arg == "--experimental" || arg == "--json" || arg == "--sarif" {
				continue
			}

			args = append(args, arg)
		}

		config.Set(configuration.RAW_CMD_ARGS, args)
	} else {
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	}

	config.Set(configuration.WORKFLOW_USE_STDIO, true)

	// run legacycli
	result, err = engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	return result, err
}
