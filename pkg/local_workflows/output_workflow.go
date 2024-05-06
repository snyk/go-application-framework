package localworkflows

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/presenters"
	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WORKFLOWID_OUTPUT_WORKFLOW workflow.Identifier = workflow.NewWorkflowIdentifier("output")

const (
	OUTPUT_CONFIG_KEY_JSON       = "json"
	OUTPUT_CONFIG_KEY_JSON_FILE  = "json-file-output"
	OUTPUT_CONFIG_KEY_SARIF      = "sarif"
	OUTPUT_CONFIG_KEY_SARIF_FILE = "sarif-file-output"
)

// InitOutputWorkflow initializes the output workflow
// The output workflow is responsible for handling the output destination of workflow data
// As part of the localworkflows package, it is registered via the localworkflows.Init method
func InitOutputWorkflow(engine workflow.Engine) error {
	outputConfig := pflag.NewFlagSet("output", pflag.ExitOnError)
	outputConfig.Bool(OUTPUT_CONFIG_KEY_JSON, false, "Print json output to console")
	outputConfig.String(OUTPUT_CONFIG_KEY_JSON_FILE, "", "Write json output to file")
	outputConfig.Bool(OUTPUT_CONFIG_KEY_SARIF, false, "Print sarif output to console")
	outputConfig.String(OUTPUT_CONFIG_KEY_SARIF_FILE, "", "Write sarif output to file")
	outputConfig.Bool(configuration.FLAG_INCLUDE_IGNORES, false, "Include ignored findings in the output")
	outputConfig.Bool(configuration.FLAG_ONLY_IGNORES, false, "Hide open issues in the output")
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

	for i := range input {
		mimeType := input[i].GetContentType()

		if strings.HasPrefix(mimeType, content_type.TEST_SUMMARY) {
			continue
		}

		contentLocation := input[i].GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Processing '%s' based on '%s' of type '%s'", input[i].GetIdentifier().String(), contentLocation, mimeType)

		if strings.Contains(mimeType, OUTPUT_CONFIG_KEY_JSON) { // handle application/json
			err := handleContentTypeJson(config, input, i, outputDestination, debugLogger)
			if err != nil {
				return output, err
			}
		} else { // handle text/pain and unknown the same way
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
	printJsonToCmd := config.GetBool(OUTPUT_CONFIG_KEY_JSON) || config.GetBool(OUTPUT_CONFIG_KEY_SARIF)
	showToHuman := !printJsonToCmd

	jsonFileName := config.GetString(OUTPUT_CONFIG_KEY_JSON_FILE)
	if len(jsonFileName) == 0 {
		jsonFileName = config.GetString(OUTPUT_CONFIG_KEY_SARIF_FILE)
	}
	writeToFile := len(jsonFileName) > 0

	singleData, ok := input[i].GetPayload().([]byte)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", input[i].GetPayload())
	}

	// are we in human readable mode
	// yes: do we have a presenter
	//  yes: use presenter
	//  no: print json to cmd
	if showToHuman && input[i].GetContentType() == content_type.SARIF_JSON {
		humanReadableSarifOutput(config, input, i, outputDestination, debugLogger, singleData)
	} else {
		// if json data is processed but non of the json related output configuration is specified, default printJsonToCmd is enabled
		if !printJsonToCmd && !writeToFile {
			printJsonToCmd = true
		}

		if printJsonToCmd {
			outputDestination.Println(string(singleData))
		}
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
	if err := outputDestination.WriteFile(jsonFileName, singleData, iUtils.FILEPERM_666); err != nil {
		return fmt.Errorf("failed to write json output: %w", err)
	}
	return nil
}

func humanReadableSarifOutput(config configuration.Configuration, input []workflow.Data, i int, outputDestination iUtils.OutputDestination, debugLogger *zerolog.Logger, singleData []byte) {
	includeOpenFindings := !config.GetBool(configuration.FLAG_ONLY_IGNORES)
	includeIgnoredFindings := config.GetBool(configuration.FLAG_INCLUDE_IGNORES) || config.GetBool(configuration.FLAG_ONLY_IGNORES)

	var sarif sarif.SarifDocument
	err := json.Unmarshal(singleData, &sarif)
	if err != nil {
		debugLogger.Println(err)
	}

	p := presenters.SarifTestResults(
		sarif,
		presenters.WithOrgName(config.GetString(configuration.ORGANIZATION)),
		presenters.WithTestPath(input[i].GetContentLocation()),
		presenters.WithIgnored(includeIgnoredFindings),
		presenters.WithOpen(includeOpenFindings),
		presenters.WithSeverityThershold(config.GetString(configuration.FLAG_SEVERITY_THRESHOLD)),
	)

	humanReadableResult, err := p.Render()
	if err != nil {
		debugLogger.Println(err)
	}

	outputDestination.Println(humanReadableResult)
}

func outputWorkflowEntryPointImpl(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	outputDestination := iUtils.NewOutputDestination()
	return outputWorkflowEntryPoint(invocation, input, outputDestination)
}
