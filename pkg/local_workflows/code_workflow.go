package localworkflows

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"

	"github.com/coryb/templatecolor"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	codeWorkflowName             = "code.test"
	codeWorkflowExperimentalFlag = configuration.FLAG_EXPERIMENTAL
)

//go:embed templates/code-test-results.tmpl
var templateString string

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
func codeWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	engine := invocationCtx.GetEngine()

	// if experimental flag is set fallback to existing behaviour
	if !config.GetBool(codeWorkflowExperimentalFlag) {
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		// run legacycli
		legacyCliResponse, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return nil, legacyCLIError
		}

		return legacyCliResponse, err
	}

	config.Set(configuration.RAW_CMD_ARGS, append(os.Args[1:], "--json"))
	config.Set(configuration.WORKFLOW_USE_STDIO, false)

	logger.Debug().Msg("code workflow start")

	// run legacycli
	legacyCliJsonData, legacyCliError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)

	logger.Debug().Msg("code workflow end")
	logger.Log().Msgf("code workflow error: %v", legacyCliError)
	// Parse the response from the legacycli workflow
	// Validate structure of JSON payload
	// and return the data in a plain text format

	// TODO: Support additional output codes
	// Out of scope: Creating a reusable Test Results interface
	// [ ] Annotate results with header/footer
	// [ ] Refactor template string out to standalone file.

	tmpl, err := template.New("test").Funcs(templatecolor.FuncMap()).Parse(templateString)
	if err != nil {
		fmt.Printf("Could not parse template: %v", err)
		panic("Could not parse template")
	}
	buff := new(bytes.Buffer)

	// Ensure that the JSON payload is an addressable struct
	type SarifTestResult struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleId  string `json:"ruleId"`
				Level   string `json:"level"`
				Info    string `json:"message.text"`
				Message struct {
					Text string `json:"text"`
				}
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							Uri string `json:"uri"`
						}
						Region struct {
							StartLine int `json:"startLine"`
						}
					}
				}
			}
		}
	}
	var sarifTestResult SarifTestResult
	jsonUnmarshalErr := json.Unmarshal(legacyCliJsonData[0].GetPayload().([]byte), &sarifTestResult)

	if jsonUnmarshalErr != nil {
		fmt.Printf("Could not unmarshal JSON: %v", jsonUnmarshalErr)
		panic("Could not unmarshal JSON")
	}

	// NOTE: Some additional transformations will be required to ensure the data
	// is in the correct format for the template
	tmplErr := tmpl.Execute(buff, sarifTestResult)

	if tmplErr != nil {
		fmt.Printf("Could not execute template: %v", tmplErr)
		panic(tmplErr)
	}

	textOutput := buff.String()
	return []workflow.Data{createCodeWorkflowData(textOutput, "text/plain")}, err
}

// createCodeWorkflowData creates a new workflow.Data object
func createCodeWorkflowData(data interface{}, contentType string) workflow.Data {
	return workflow.NewData(
		// use new type identifier when creating new data
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, whoAmIworkflowName),
		contentType,
		data,
	)
}
