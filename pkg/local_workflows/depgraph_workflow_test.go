package localworkflows

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_Depgraph_extractLegacyCLIError_extractError(t *testing.T) {

	expectedMsgJson := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	inputError := &exec.ExitError{}
	data := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "something"), "application/json", []byte(expectedMsgJson))

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, "Hello Error", outputError.Error())

	_, ok := outputError.(*LegacyCliJsonError)
	assert.True(t, ok)
}

func Test_Depgraph_extractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "something"), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, inputError.Error(), outputError.Error())
}

func Test_Depgraph_InitDepGraphWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitDepGraphWorkflow(engine)
	assert.Nil(t, err)

	allProjects := config.Get("all-projects")
	assert.Equal(t, false, allProjects)

	inputFile := config.Get("file")
	assert.Equal(t, "", inputFile)
}

func Test_Depgraph_depgraphWorkflowEntryPoint(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()

	payload := `
	DepGraph data:
	{
		"schemaVersion": "1.2.0",
		"pkgManager": {
			"name": "npm"
		},
		"pkgs": [
			{
				"id": "goof@1.0.1",
				"info": {
					"name": "goof",
					"version": "1.0.1"
				}
			}
		],
		"graph": {
			"rootNodeId": "root-node",
			"nodes": [
				{
					"nodeId": "root-node",
					"pkgId": "goof@1.0.1",
					"deps": [
						{
							"nodeId": "adm-zip@0.4.7"
						},
						{
							"nodeId": "body-parser@1.9.0"
						}
					]
				}
			]
		}
	}
	DepGraph target:
	package-lock.json
	DepGraph end`

	t.Run("should return a depGraphList", func(t *testing.T) {
		// setup
		expectedJson := `
		{
			"schemaVersion": "1.2.0",
			"pkgManager": {
				"name": "npm"
			},
			"pkgs": [
				{
					"id": "goof@1.0.1",
					"info": {
						"name": "goof",
						"version": "1.0.1"
					}
				}
			],
			"graph": {
				"rootNodeId": "root-node",
				"nodes": [
					{
						"nodeId": "root-node",
						"pkgId": "goof@1.0.1",
						"deps": [
							{
								"nodeId": "adm-zip@0.4.7"
							},
							{
								"nodeId": "body-parser@1.9.0"
							}
						]
					}
				]
			}
		}`

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		depGraphList, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		var expected interface{}
		err = json.Unmarshal([]byte(expectedJson), &expected)
		assert.Nil(t, err)

		var actual interface{}
		err = json.Unmarshal(depGraphList[0].GetPayload().([]byte), &actual)
		assert.Nil(t, err)

		assert.Equal(t, expected, actual)
	})

	t.Run("should support 'debug' flag", func(t *testing.T) {
		// setup
		config.Set(configuration.DEBUG, true)

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--debug")
	})

	t.Run("should support 'fail-fast' flag", func(t *testing.T) {
		// setup
		config.Set("fail-fast", true)

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--fail-fast")
	})

	t.Run("should support 'all-projects' flag", func(t *testing.T) {
		// setup
		config.Set("all-projects", true)

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--all-projects")
	})

	t.Run("should support custom 'targetDirectory'", func(t *testing.T) {
		// setup
		config.Set("targetDirectory", "path/to/target")

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "path/to/target")
	})

	t.Run("should support 'file' flag", func(t *testing.T) {
		// setup
		config.Set("file", "path/to/target/file.js")

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--file=path/to/target/file.js")
	})

	t.Run("should support 'exclude' flag", func(t *testing.T) {
		// setup
		config.Set("exclude", "path/to/target/file.js")

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--exclude=path/to/target/file.js")
	})

	t.Run("should support 'detection-depth' flag", func(t *testing.T) {
		// setup
		config.Set("detection-depth", "42")

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--detection-depth=42")
	})

	t.Run("should support 'prune-repeated-subdependencies' flag", func(t *testing.T) {
		// setup
		config.Set("prune-repeated-subdependencies", true)

		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--prune-repeated-subdependencies")
	})

	t.Run("should error if no dependency graphs found", func(t *testing.T) {
		dataIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte{})

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Equal(t, "No dependency graphs found", err.Error())
	})
}
