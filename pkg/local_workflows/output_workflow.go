package localworkflows

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var WORKFLOWID_OUTPUT_WORKFLOW workflow.Identifier = workflow.NewWorkflowIdentifier("output")

func InitOutputWorkflow(engine workflow.Engine) error {
	outputConfig := pflag.NewFlagSet("output", pflag.ExitOnError)
	outputConfig.Bool("json", false, "Print json output to console")
	outputConfig.String("json-file-output", "", "Write json output to file")

	entry, err := engine.Register(WORKFLOWID_OUTPUT_WORKFLOW, workflow.ConfigurationOptionsFromFlagset(outputConfig), outputWorkflowEntryPoint)
	entry.SetVisibility(false)

	return err
}

func outputWorkflowEntryPoint(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	err = nil
	output = []workflow.Data{}

	config := invocation.GetConfiguration()
	debugLogger := invocation.GetLogger()

	printJsonToCmd := config.GetBool("json")
	writeJsonToFile := config.GetString("json-file-output")

	for i := range input {
		mimeType := input[i].GetContentType()
		contentLocation := input[i].GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Processing '%s' based on '%s' of type '%s'\n", input[i].GetIdentifier().String(), contentLocation, mimeType)

		if strings.Contains(mimeType, "json") { // handle application/json
			singleData := input[i].GetPayload().([]byte)

			// if json data is processed but non of the json related output configuration is specified, default printJsonToCmd is enabled
			if printJsonToCmd == false && len(writeJsonToFile) == 0 {
				printJsonToCmd = true
			}

			if printJsonToCmd {
				fmt.Println(string(singleData))
			}

			if len(writeJsonToFile) > 0 {
				debugLogger.Printf("Writing '%s' JSON of length %d to '%s'\n", input[i].GetIdentifier().String(), len(singleData), writeJsonToFile)

				os.Remove(writeJsonToFile)
				os.WriteFile(writeJsonToFile, singleData, fs.FileMode(0666))
			}
		} else if mimeType == "text/plain" { // handle text/pain
			singleData := input[i].GetPayload().([]byte)
			fmt.Println(string(singleData))
		} else {
			err := fmt.Errorf("Unsupported output type: %s", mimeType)
			return output, err
		}
	}

	return output, err
}
