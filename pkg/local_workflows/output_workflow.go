package localworkflows

import (
	"fmt"
	"strings"

	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var (
	WORKFLOWID_OUTPUT_WORKFLOW workflow.Identifier = Output.Identifier()

	// The output workflow is responsible for handling the output destination of workflow data
	// As part of the localworkflows package, it is registered via the localworkflows.Init method
	Output = &outputWorkflow{
		Workflow: &workflow.Workflow{
			Name:    "output",
			Visible: false,
			// we don't set any flags here, because we overwrite the GetFlags function.
			Flags: nil,
		},
		destination: iUtils.NewOutputDestination(),

		jsonFlag: workflow.Flag[bool]{
			Name:         OUTPUT_CONFIG_KEY_JSON,
			DefaultValue: false,
			Usage:        "Print json output to console",
		},
		jsonFileFlag: workflow.Flag[string]{
			Name:         OUTPUT_CONFIG_KEY_JSON_FILE,
			DefaultValue: "",
			Usage:        "Write json output to file",
		},
	}
)

const (
	OUTPUT_CONFIG_KEY_JSON      = "json"
	OUTPUT_CONFIG_KEY_JSON_FILE = "json-file-output"
)

// InitOutputWorkflow initializes the output workflow
// The output workflow is responsible for handling the output destination of workflow data
// As part of the localworkflows package, it is registered via the localworkflows.Init method
// Deprecated: use `workflow.Register(Output, engine)` directly.
func InitOutputWorkflow(engine workflow.Engine) error {
	return workflow.Register(Output, engine)
}

type outputWorkflow struct {
	*workflow.Workflow
	destination  iUtils.OutputDestination
	jsonFlag     workflow.Flag[bool]
	jsonFileFlag workflow.Flag[string]
}

func (o *outputWorkflow) GetFlags() workflow.Flags {
	return workflow.Flags{o.jsonFlag, o.jsonFileFlag}
}

func (o outputWorkflow) Entrypoint(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	var (
		config      = invocation.GetConfiguration()
		debugLogger = o.Logger(invocation)

		printJsonToCmd  = o.jsonFlag.Value(config)
		writeJsonToFile = o.jsonFileFlag.Value(config)
	)

	for _, in := range input {
		mimeType := in.GetContentType()
		contentLocation := in.GetContentLocation()
		if contentLocation == "" {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Processing '%s' based on '%s' of type '%s'\n", in.GetIdentifier().String(), contentLocation, mimeType)

		if strings.Contains(mimeType, OUTPUT_CONFIG_KEY_JSON) { // handle application/json
			singleData := in.GetPayload().([]byte)

			// if json data is processed but non of the json related output configuration is specified, default printJsonToCmd is enabled
			if printJsonToCmd == false && len(writeJsonToFile) == 0 {
				printJsonToCmd = true
			}

			if printJsonToCmd {
				o.destination.Println(string(singleData))
			}

			if len(writeJsonToFile) > 0 {
				debugLogger.Printf("Writing '%s' JSON of length %d to '%s'\n", in.GetIdentifier().String(), len(singleData), writeJsonToFile)

				o.destination.Remove(writeJsonToFile)
				o.destination.WriteFile(writeJsonToFile, singleData, iUtils.FILEPERM_666)
			}
		} else { // handle text/plain and unknown the same way
			// try to convert payload to a string
			singleDataAsString := ""
			singleData, typeCastSuccessful := in.GetPayload().([]byte)
			if !typeCastSuccessful {
				singleDataAsString, typeCastSuccessful = in.GetPayload().(string)
				if !typeCastSuccessful {
					return nil, fmt.Errorf("Unsupported output type: %s", mimeType)
				}
			} else {
				singleDataAsString = string(singleData)
			}

			o.destination.Println(singleDataAsString)
		}
	}

	return output, nil
}
