package localworkflows

import (
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

func Test_Depgraph_depgraphWorkflowEntryPoint(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	t.Run("should return a depGraphList", func(t *testing.T) {
		// setup
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

		data := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "something"), "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// invocation context mocks
		invocationContextMock.EXPECT().GetEngine().Return(engineMock).Times(1)
		invocationContextMock.EXPECT().GetConfiguration().Return(config).Times(1)
		invocationContextMock.EXPECT().GetLogger().Return(logger).Times(1)
		// execute
		depGraphList, err := depgraphWorkflowEntryPoint(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{data}, depGraphList)
	})
}
