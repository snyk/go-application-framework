package localworkflows

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
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

	config := invocation.GetConfiguration()
	debugLogger := invocation.GetEnhancedLogger()
	writers := output_workflow.GetWritersFromConfiguration(config, outputDestination)
	debugLogger.Info().Msgf("Available writers: %d", writers.Length())

	// Handle UFM models, if none found, continue with the rest
	input, err := output_workflow.HandleContentTypeUnifiedModel(input, invocation, writers)
	if err != nil {
		return output, err
	}

	// Handle findings models, if none found, continue with the rest
	input, err = output_workflow.HandleContentTypeFindingsModel(input, invocation, writers)
	if err != nil {
		return output, err
	}

	for i := range input {
		mimeType := input[i].GetContentType()

		if strings.HasPrefix(mimeType, content_type.TEST_SUMMARY) {
			// skip test summary output
			continue
		}

		contentLocation := input[i].GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Processing '%s' based on '%s' of type '%s'", input[i].GetIdentifier().String(), contentLocation, mimeType)

		// handle text/plain and unknown the same way
		otherHandlerMimetypes := []string{output_workflow.DEFAULT_MIME_TYPE}

		if strings.Contains(mimeType, output_workflow.OUTPUT_CONFIG_KEY_JSON) { // handle application/json
			otherHandlerMimetypes = []string{output_workflow.JSON_MIME_TYPE, output_workflow.SARIF_MIME_TYPE}
		}

		err = handleContentTypeOthers(debugLogger, input[i], mimeType, writers, otherHandlerMimetypes)
		if err != nil {
			return output, err
		}
	}

	return output, nil
}

func handleContentTypeOthers(debugLogger *zerolog.Logger, input workflow.Data, mimeType string, writers output_workflow.WriterMap, supportedMimeTypes []string) error {
	// try to convert payload to a string
	var singleDataAsString string
	singleData, typeCastSuccessful := input.GetPayload().([]byte)
	if !typeCastSuccessful {
		singleDataAsString, typeCastSuccessful = input.GetPayload().(string)
		if !typeCastSuccessful {
			return fmt.Errorf("unsupported output type: %s", mimeType)
		}
	} else {
		singleDataAsString = string(singleData)
	}

	for _, mimetype := range supportedMimeTypes {
		writer := writers.PopWritersByMimetype(mimetype)
		if len(writer) == 0 {
			continue
		}

		debugLogger.Info().Msgf("Handle Other: Using Writer for: %s", mimetype)
		for _, w := range writer {
			_, err := fmt.Fprintln(w.GetWriter(), singleDataAsString)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func outputWorkflowEntryPointImpl(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	outputDestination := iUtils.NewOutputDestination()
	return outputWorkflowEntryPoint(invocation, input, outputDestination)
}
