package localworkflows

import (
	"os"
	"slices"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	codeWorkflowName             = "code.test"
	codeWorkflowExperimentalFlag = configuration.FLAG_EXPERIMENTAL
)

func GetCodeFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(codeWorkflowName, pflag.ExitOnError)

	// add flags here
	flagSet.Bool("sarif", false, "Output in sarif format")
	flagSet.Bool("json", false, "Output in json format")
	flagSet.Bool("report", false, "Share results with the Snyk Web UI")
	flagSet.String("severity-threshold", "", "Minimum severity level to report (low|medium|high)")
	flagSet.String("sarif-file-output", "", "Save test output in SARIF format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --sarif option.")
	flagSet.String("json-file-output", "", "Save test output in JSON format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --json option.")
	flagSet.String("project-name", "", "The name of the project to test.")
	flagSet.String("project-id", "", "The unique identifier of the project to test.")
	flagSet.String("commit-id", "", "The unique identifier of the commit to test.")
	flagSet.String("target-name", "", "The name of the target to test.")
	flagSet.String("target-file", "", "The path to the target file to test.")
	flagSet.String("remote-repo-url", "", "The URL of the remote repository to test.")
	flagSet.Bool("experimental", false, "Enable experimental code test command")

	return flagSet
}

// WORKFLOWID_CODE defines a new workflow identifier
var WORKFLOWID_CODE workflow.Identifier = workflow.NewWorkflowIdentifier(codeWorkflowName)

// InitCodeWorkflow initializes the code workflow before registering it with the engine.
func InitCodeWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := GetCodeFlagSet()
	_, err := engine.Register(WORKFLOWID_CODE, workflow.ConfigurationOptionsFromFlagset(flags), codeWorkflowEntryPoint)
	return err
}

// codeWorkflowEntryPoint is the entry point for the code workflow.
// it provides a wrapper for the legacycli workflow
func codeWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
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

	logger.Debug().Msg("code workflow start")

	if config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES) {
		logger.Debug().Msg("Ignores: Consistent")
	} else {
		logger.Debug().Msg("Ignores: legacy")
	}

	// run legacycli
	result, err = engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)

	return result, err
}
