package localworkflows

import (
	"encoding/json"
	"log"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_Output_InitOutputWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitOutputWorkflow(engine)
	assert.Nil(t, err)

	json := config.Get("json")
	assert.Equal(t, false, json)

	jsonFileOutput := config.Get("json-file-output")
	assert.Equal(t, "", jsonFileOutput)
}

func Test_Output_outputWorkflowEntryPoint(t *testing.T) {
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
