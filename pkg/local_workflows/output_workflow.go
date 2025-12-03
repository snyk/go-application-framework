package localworkflows

import (
	"errors"

	"github.com/spf13/pflag"

	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/output_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_OUTPUT_WORKFLOW workflow.Identifier = workflow.NewWorkflowIdentifier("output")

// InitOutputWorkflow initializes the output workflow
// The output workflow is responsible for handling the output destination of workflow data
// As part of the localworkflows package, it is registered via the localworkflows.Init method
func InitOutputWorkflow(engine workflow.Engine) error {
	outputConfig := pflag.NewFlagSet("output", pflag.ExitOnError)
	outputConfig.Bool(output_workflow.OUTPUT_CONFIG_KEY_JSON, false, "Print json output to console")
	outputConfig.String(output_workflow.OUTPUT_CONFIG_KEY_JSON_FILE, "", "Write json output to file")
	outputConfig.Bool(output_workflow.OUTPUT_CONFIG_KEY_SARIF, false, "Print sarif output to console")
	outputConfig.String(output_workflow.OUTPUT_CONFIG_KEY_SARIF_FILE, "", "Write sarif output to file")
	outputConfig.Bool(configuration.FLAG_INCLUDE_IGNORES, false, "Include ignored findings in the output")
	outputConfig.String(configuration.FLAG_SEVERITY_THRESHOLD, "low", "Severity threshold for findings to be included in the output")

	entry, err := engine.Register(WORKFLOWID_OUTPUT_WORKFLOW, workflow.ConfigurationOptionsFromFlagset(outputConfig), outputWorkflowEntryPointImpl)
	entry.SetVisibility(false)

	return err
}

// outputWorkflowEntryPoint defines the output entry point
// the entry point is called by the engine when the workflow is invoked
func outputWorkflowEntryPoint(invocation workflow.InvocationContext, input []workflow.Data, outputDestination iUtils.OutputDestination) ([]workflow.Data, error) {
	output := []workflow.Data{}

	var finalError error
	config := invocation.GetConfiguration()
	debugLogger := invocation.GetEnhancedLogger()
	writers := output_workflow.GetWritersFromConfiguration(config, outputDestination)
	debugLogger.Info().Msgf("Available writers (count: %d):", writers.Length())
	debugLogger.Info().Msg(writers.String())

	// Handle UFM models, if none found, continue with the rest
	input, err := output_workflow.HandleContentTypeUnifiedModel(input, invocation, writers)
	if err != nil {
		finalError = errors.Join(finalError, err)
	}

	// Handle findings models, if none found, continue with the rest
	input, err = output_workflow.HandleContentTypeFindingsModel(input, invocation, writers)
	if err != nil {
		finalError = errors.Join(finalError, err)
	}

	// Handle remaining data
	input, err = output_workflow.HandleContentTypeOther(input, invocation, writers)
	if err != nil {
		finalError = errors.Join(finalError, err)
	}

	if writers.Length() > 0 {
		debugLogger.Warn().Msg("Unused writers:")
		for _, t := range writers.AvailableMimetypes() {
			debugLogger.Warn().Msgf(" - %s", t)
		}
	}

	if len(input) > 0 {
		debugLogger.Warn().Msg("Unused input:")
		for _, t := range input {
			debugLogger.Warn().Msgf(" - %s", t.GetContentType())
		}
	}

	return output, finalError
}

func outputWorkflowEntryPointImpl(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	outputDestination := iUtils.NewOutputDestination()
	return outputWorkflowEntryPoint(invocation, input, outputDestination)
}
