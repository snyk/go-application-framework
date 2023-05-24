package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var WORKFLOWID_DEPGRAPH_WORKFLOW workflow.Identifier = workflow.NewWorkflowIdentifier("depgraph")
var DATATYPEID_DEPGRAPH workflow.Identifier = workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")

// LegacyCliJsonError is the error type returned by the legacy cli
type LegacyCliJsonError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
}

// Error returns the LegacyCliJsonError error message
func (e *LegacyCliJsonError) Error() string {
	return e.ErrorMsg
}

// extractLegacyCLIError extracts the error message from the legacy cli if possible
func extractLegacyCLIError(input error, data []workflow.Data) (output error) {
	output = input

	// extract error from legacy cli if possible and wrap it in an error instance
	_, isExitError := input.(*exec.ExitError)
	if isExitError && data != nil && len(data) > 0 {
		bytes := data[0].GetPayload().([]byte)

		var decodedError LegacyCliJsonError
		err := json.Unmarshal(bytes, &decodedError)
		if err == nil {
			output = &decodedError
		}

	}

	return output
}

// InitDepGraphWorkflow initializes the depgraph workflow
// The depgraph workflow is responsible for handling the depgraph data
// As part of the localworkflows package, it is registered via the localworkflows.Init method
func InitDepGraphWorkflow(engine workflow.Engine) error {
	depGraphConfig := pflag.NewFlagSet("depgraph", pflag.ExitOnError)
	depGraphConfig.Bool("all-projects", false, "Enable all projects")
	depGraphConfig.String("file", "", "Input file")
	depGraphConfig.String("detection-depth", "", "Detection depth")
	depGraphConfig.BoolP("prune-repeated-subdependencies", "p", false, "Prune repeated sub-dependencies")

	_, err := engine.Register(WORKFLOWID_DEPGRAPH_WORKFLOW, workflow.ConfigurationOptionsFromFlagset(depGraphConfig), depgraphWorkflowEntryPoint)
	return err
}

// depgraphWorkflowEntryPoint defines the depgraph entry point
// the entry point is called by the engine when the workflow is invoked
func depgraphWorkflowEntryPoint(invocation workflow.InvocationContext, input []workflow.Data) (depGraphList []workflow.Data, err error) {
	err = nil
	depGraphList = []workflow.Data{}

	engine := invocation.GetEngine()
	config := invocation.GetConfiguration()
	debugLogger := invocation.GetLogger()

	debugLogger.Println("depgraph workflow start")

	jsonSeparatorEnd := []byte("DepGraph end")
	jsonSeparatorData := []byte("DepGraph data:")
	jsonSeparatorTarget := []byte("DepGraph target:")

	// prepare invocation of the legacy cli
	snykCmdArguments := []string{"test", "--print-graph", "--json"}
	if allProjects := config.GetBool("all-projects"); allProjects {
		snykCmdArguments = append(snykCmdArguments, "--all-projects")
	}

	if exclude := config.GetString("exclude"); exclude != "" {
		snykCmdArguments = append(snykCmdArguments, "--exclude="+exclude)
		debugLogger.Println("Exclude:", exclude)
	}

	if detectionDepth := config.GetString("detection-depth"); detectionDepth != "" {
		snykCmdArguments = append(snykCmdArguments, "--detection-depth="+detectionDepth)
		debugLogger.Println("Detection depth:", detectionDepth)
	}

	if pruneRepeatedSubDependencies := config.GetBool("prune-repeated-subdependencies"); pruneRepeatedSubDependencies {
		snykCmdArguments = append(snykCmdArguments, "--prune-repeated-subdependencies")
		debugLogger.Println("Prune repeated sub-dependencies:", pruneRepeatedSubDependencies)
	}

	if targetDirectory := config.GetString("targetDirectory"); err == nil {
		snykCmdArguments = append(snykCmdArguments, targetDirectory)
	}

	if unmanaged := config.GetBool("unmanaged"); unmanaged {
		snykCmdArguments = append(snykCmdArguments, "--unmanaged")
	}

	if file := config.GetString("file"); len(file) > 0 {
		snykCmdArguments = append(snykCmdArguments, "--file="+file)
		debugLogger.Println("File:", file)
	}

	config.Set(configuration.RAW_CMD_ARGS, snykCmdArguments)
	legacyData, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	if legacyCLIError != nil {
		legacyCLIError = extractLegacyCLIError(legacyCLIError, legacyData)
		return depGraphList, legacyCLIError
	}

	snykOutput := legacyData[0].GetPayload().([]byte)

	snykOutputLength := len(snykOutput)
	if snykOutputLength <= 0 {
		return depGraphList, fmt.Errorf("No dependency graphs found")
	}

	// split up dependency data from legacy cli
	separatedJsonRawData := bytes.Split(snykOutput, jsonSeparatorEnd)
	for i := range separatedJsonRawData {
		rawData := separatedJsonRawData[i]
		if bytes.Contains(rawData, jsonSeparatorData) {
			graphStartIndex := bytes.Index(rawData, jsonSeparatorData) + len(jsonSeparatorData)
			graphEndIndex := bytes.Index(rawData, jsonSeparatorTarget)
			targetNameStartIndex := graphEndIndex + len(jsonSeparatorTarget)
			targetNameEndIndex := len(rawData) - 1

			targetName := rawData[targetNameStartIndex:targetNameEndIndex]
			depGraphJson := rawData[graphStartIndex:graphEndIndex]

			data := workflow.NewData(DATATYPEID_DEPGRAPH, "application/json", depGraphJson)
			data.SetMetaData("Content-Location", strings.TrimSpace(string(targetName)))
			depGraphList = append(depGraphList, data)
		}
	}

	debugLogger.Printf("depgraph workflow done (%d)", len(depGraphList))

	return depGraphList, err
}
