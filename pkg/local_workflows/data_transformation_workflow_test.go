package localworkflows

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func setupMockTransformationContext(t *testing.T, fflagEnabled bool) *mocks.MockInvocationContext {
	t.Helper()

	// setup
	logger := zerolog.Logger{}
	config := configuration.New()
	config.Set(configuration.FF_TRANSFORMATION_WORKFLOW, fflagEnabled)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	// setup invocation context
	invocationContextMock.EXPECT().GetConfiguration().Return(config)
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger)

	return invocationContextMock
}

func Test_DataTransformation_appendsTransformedInput(t *testing.T) {
	invocationContext := setupMockTransformationContext(t, true)
	logger := zerolog.Logger{}
	input := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			content_type.SARIF_JSON, nil, workflow.WithLogger(&logger)),
	}
	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.NoError(t, err)
	assert.Len(t, output, 2)
}

func Test_DataTransformation_onlyWithTransformationWorkflowEnabled(t *testing.T) {
	invocationContext := setupMockTransformationContext(t, false)
	logger := zerolog.Logger{}
	input := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			"application/json", nil, workflow.WithLogger(&logger)),
	}
	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.NoError(t, err)
	assert.Len(t, output, 1)
}

func getTestSarifBytes(t *testing.T) sarif.SarifDocument {
	t.Helper()

	sarifDoc := sarif.SarifDocument{
		Runs: []sarif.Run{{
			Results: []sarif.Result{
				{Level: "error"},
				{Level: "warning"},
			},
			Properties: sarif.RunProperties{
				Coverage: []struct {
					Files       int    `json:"files"`
					IsSupported bool   `json:"isSupported"`
					Lang        string `json:"lang"`
					Type        string `json:"type"`
				}{{
					Files:       2,
					IsSupported: true,
					Lang:        "",
					Type:        "",
				}},
			},
		},
			{
				Results: []sarif.Result{
					{Level: "error"},
					{Level: "error", Suppressions: make([]sarif.Suppression, 1)},
				},
			},
			{
				Results: []sarif.Result{
					{Level: "note", Suppressions: make([]sarif.Suppression, 1)},
				},
			}},
	}

	return sarifDoc
}

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on windows device [CLI-514]")
	}
}

func Test_DataTransformation_withSarifData(t *testing.T) {
	skipWindows(t)

	invocationContext := setupMockTransformationContext(t, true)
	logger := zerolog.Logger{}
	input := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			content_type.SARIF_JSON,
			loadJsonFile(t, "sarif-juice-shop.json"),
			workflow.WithLogger(&logger)),
	}
	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.NoError(t, err)
	assert.Len(t, output, 2)

	var transformedOutput workflow.Data

	// Output contains formatted finding response
	for _, data := range output {
		mimeType := data.GetContentType()

		if strings.EqualFold(mimeType, content_type.LOCAL_FINDING_MODEL) {
			transformedOutput = data
		}
	}

	var localFinding = local_models.LocalFinding{}
	p, ok := transformedOutput.GetPayload().([]byte)

	assert.True(t, ok)

	err = json.Unmarshal(p, &localFinding)
	assert.NoError(t, err)
	assert.IsType(t, local_models.LocalFinding{}, localFinding)
	assert.Len(t, localFinding.Findings, 278)
	// TODO: Validate passed prop
	assert.Equal(t, "662d6134-2c32-55f7-9717-d60add450b1b", localFinding.Findings[0].Id.String())
}

func Test_DataTransformation_withUnsupportedInput(t *testing.T) {
	invocationContext := setupMockTransformationContext(t, true)
	logger := zerolog.Logger{}
	input := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			"application/json",
			getTestSarifBytes(t),
			workflow.WithLogger(&logger)),
	}
	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.NoError(t, err)
	assert.Len(t, output, 1)

	var transformedOutput workflow.Data

	// Output contains formatted finding response
	for _, data := range output {
		mimeType := data.GetContentType()

		if strings.EqualFold(mimeType, content_type.LOCAL_FINDING_MODEL) {
			transformedOutput = data
		}
	}
	assert.Nil(t, transformedOutput)
}

func loadJsonFile(t *testing.T, filename string) []byte {
	t.Helper()

	jsonFile, err := os.Open("./testdata/" + filename)
	assert.NoError(t, err, "failed to load json")
	defer func(jsonFile *os.File) {
		jsonErr := jsonFile.Close()
		assert.NoError(t, jsonErr)
	}(jsonFile)
	byteValue, err := io.ReadAll(jsonFile)
	assert.NoError(t, err)
	return byteValue
}
