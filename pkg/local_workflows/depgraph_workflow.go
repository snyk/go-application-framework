package localworkflows

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var WORKFLOWID_DEPGRAPH_WORKFLOW workflow.Identifier = workflow.NewWorkflowIdentifier("depgraph")
var DATATYPEID_DEPGRAPH workflow.Identifier = workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")

func InitDepGraphWorkflow(engine workflow.Engine) error {
	depGraphConfig := pflag.NewFlagSet("depgraph", pflag.ExitOnError)
	depGraphConfig.Bool("all-projects", false, "Enable all projects")
	depGraphConfig.String("file", "", "Input file")

	_, err := engine.Register(WORKFLOWID_DEPGRAPH_WORKFLOW, workflow.ConfigurationOptionsFromFlagset(depGraphConfig), depgraphWorkflowEntryPoint)
	return err
}

func depgraphWorkflowEntryPoint(invocation workflow.InvocationContext, input []workflow.Data) (depGraphList []workflow.Data, err error) {
	err = nil
	depGraphList = []workflow.Data{}

	engine := invocation.GetEngine()
	config := invocation.GetConfiguration()
	debugLogger := invocation.GetLogger()

	jsonSeparatorEnd := []byte("DepGraph end")
	jsonSeparatorData := []byte("DepGraph data:")
	jsonSeparatorTarget := []byte("DepGraph target:")

	// prepare invocation of the legacy cli
	snykCmdArguments := []string{"test", "--print-graph", "--json"}
	if allProjects := config.GetBool("all-projects"); allProjects {
		snykCmdArguments = append(snykCmdArguments, "--all-projects")
	}

	if targetDirectory := config.GetString("targetDirectory"); err == nil {
		snykCmdArguments = append(snykCmdArguments, targetDirectory)
	}

	if file := config.GetString("file"); len(file) > 0 {
		snykCmdArguments = append(snykCmdArguments, "--file="+file)
		debugLogger.Println("File:", file)
	}

	config.Set(configuration.RAW_CMD_ARGS, snykCmdArguments)
	legacyData, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	if legacyCLIError != nil {
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
