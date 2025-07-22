package localworkflows

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/presenters"
	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
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

func filterSummaryOutput(config configuration.Configuration, input workflow.Data, logger *zerolog.Logger) (workflow.Data, error) {
	// Parse the summary data
	summary := json_schemas.NewTestSummary("", "")
	payload, ok := input.GetPayload().([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type: %T", input.GetPayload())
	}
	err := json.Unmarshal(payload, &summary)
	if err != nil {
		return input, err
	}

	minSeverity := config.GetString(configuration.FLAG_SEVERITY_THRESHOLD)
	filteredSeverityOrderAsc := presenters.FilterSeverityASC(summary.SeverityOrderAsc, minSeverity)

	// Filter out the results based on the configuration
	var filteredResults []json_schemas.TestSummaryResult

	for _, severity := range filteredSeverityOrderAsc {
		for _, result := range summary.Results {
			if severity == result.Severity {
				filteredResults = append(filteredResults, result)
			}
		}
	}

	summary.Results = filteredResults

	bytes, err := json.Marshal(summary)
	if err != nil {
		return input, err
	}

	workflowId := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "FilterTestSummary")
	output := workflow.NewDataFromInput(
		input,
		workflowId,
		content_type.TEST_SUMMARY,
		bytes,
		workflow.WithLogger(logger))

	return output, nil
}

// outputWorkflowEntryPoint defines the output entry point
// the entry point is called by the engine when the workflow is invoked
func outputWorkflowEntryPoint(invocation workflow.InvocationContext, input []workflow.Data, outputDestination iUtils.OutputDestination) ([]workflow.Data, error) {
	output := []workflow.Data{}

	config := invocation.GetConfiguration()
	debugLogger := invocation.GetEnhancedLogger()

	// Handle findings models, if none found, continue with the rest
	input, err := output_workflow.HandleContentTypeFindingsModel(input, invocation, outputDestination)
	if err != nil {
		return output, err
	}

	input, err = output_workflow.HandleContentTypeShimModel(input, invocation, outputDestination)
	if err != nil {
		return output, err
	}

	for i := range input {
		mimeType := input[i].GetContentType()

		if strings.HasPrefix(mimeType, content_type.TEST_SUMMARY) {
			outputSummary, err := filterSummaryOutput(config, input[i], debugLogger)
			if err != nil {
				debugLogger.Warn().Err(err).Msg("Failed to filter test summary output")
				output = append(output, input[i])
			}
			output = append(output, outputSummary)
			continue
		}

		contentLocation := input[i].GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Processing '%s' based on '%s' of type '%s'", input[i].GetIdentifier().String(), contentLocation, mimeType)

		if strings.Contains(mimeType, output_workflow.OUTPUT_CONFIG_KEY_JSON) { // handle application/json
			err := handleContentTypeJson(config, input, i, outputDestination, debugLogger)
			if err != nil {
				return output, err
			}
		} else { // handle text/plain and unknown the same way
			err := handleContentTypeOthers(input, i, mimeType, outputDestination)
			if err != nil {
				return output, err
			}
		}
	}

	return output, nil
}

func handleContentTypeOthers(input []workflow.Data, i int, mimeType string, outputDestination iUtils.OutputDestination) error {
	// try to convert payload to a string
	var singleDataAsString string
	singleData, typeCastSuccessful := input[i].GetPayload().([]byte)
	if !typeCastSuccessful {
		singleDataAsString, typeCastSuccessful = input[i].GetPayload().(string)
		if !typeCastSuccessful {
			return fmt.Errorf("unsupported output type: %s", mimeType)
		}
	} else {
		singleDataAsString = string(singleData)
	}

	outputDestination.Println(singleDataAsString)
	return nil
}

func handleContentTypeJson(config configuration.Configuration, input []workflow.Data, i int, outputDestination iUtils.OutputDestination, debugLogger *zerolog.Logger) error {
	printJsonToCmd := config.GetBool(output_workflow.OUTPUT_CONFIG_KEY_JSON) || config.GetBool(output_workflow.OUTPUT_CONFIG_KEY_SARIF)

	jsonFileName := config.GetString(output_workflow.OUTPUT_CONFIG_KEY_JSON_FILE)
	if len(jsonFileName) == 0 {
		jsonFileName = config.GetString(output_workflow.OUTPUT_CONFIG_KEY_SARIF_FILE)
	}
	writeToFile := len(jsonFileName) > 0

	singleData, ok := input[i].GetPayload().([]byte)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", input[i].GetPayload())
	}

	// if json data is processed but non of the json related output configuration is specified, default printJsonToCmd is enabled
	if !printJsonToCmd && !writeToFile {
		printJsonToCmd = true
	}

	if printJsonToCmd {
		outputDestination.Println(string(singleData))
	}

	if writeToFile {
		err := jsonWriteToFile(debugLogger, input, i, singleData, jsonFileName, outputDestination)
		if err != nil {
			return err
		}
	}
	return nil
}

func jsonWriteToFile(debugLogger *zerolog.Logger, input []workflow.Data, i int, singleData []byte, jsonFileName string, outputDestination iUtils.OutputDestination) error {
	debugLogger.Printf("Writing '%s' JSON of length %d to '%s'", input[i].GetIdentifier().String(), len(singleData), jsonFileName)

	if err := outputDestination.Remove(jsonFileName); err != nil {
		return fmt.Errorf("failed to remove existing output file: %w", err)
	}

	if err := iUtils.CreateFilePath(jsonFileName); err != nil {
		return fmt.Errorf("failed to create output folder: %w", err)
	}

	if err := outputDestination.WriteFile(jsonFileName, singleData, iUtils.FILEPERM_666); err != nil {
		return fmt.Errorf("failed to write json output: %w", err)
	}
	return nil
}

func outputWorkflowEntryPointImpl(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	outputDestination := iUtils.NewOutputDestination()
	return outputWorkflowEntryPoint(invocation, input, outputDestination)
}
