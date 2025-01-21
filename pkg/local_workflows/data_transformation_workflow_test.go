package localworkflows

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
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
	userInterface := ui.DefaultUi()

	// setup invocation context
	invocationContextMock.EXPECT().GetConfiguration().Return(config)
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger)
	invocationContextMock.EXPECT().GetUserInterface().Return(userInterface).AnyTimes()

	return invocationContextMock
}

func Test_DataTransformation_with_incomplete_data(t *testing.T) {
	invocationContext := setupMockTransformationContext(t, true)
	logger := zerolog.Logger{}
	input := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			content_type.SARIF_JSON, nil, workflow.WithLogger(&logger)),
	}
	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.NoError(t, err)
	assert.Len(t, output, 1)
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

func Test_DataTransformation_with_Incomplete_Input(t *testing.T) {
	invocationContext := setupMockTransformationContext(t, true)
	input := []workflow.Data{}
	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.NoError(t, err)
	assert.Len(t, output, 0)
	assert.Equal(t, input, output)
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

func Test_DataTransformation_with_Sarif_and_SummaryData(t *testing.T) {
	invocationContext := setupMockTransformationContext(t, true)
	logger := zerolog.Logger{}
	input := []workflow.Data{
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			content_type.SARIF_JSON,
			loadJsonFile(t, "sarif-juice-shop.json"),
			workflow.WithLogger(&logger)),
		workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_DATATRANSFORMATION, DataTransformationWorkflowName),
			content_type.TEST_SUMMARY,
			loadJsonFile(t, "juice-shop-summary.json"),
			workflow.WithLogger(&logger)),
	}

	output, err := dataTransformationEntryPoint(invocationContext, input)
	assert.Nil(t, err)
	assert.Len(t, output, 2)

	var transformedOutput workflow.Data

	// Output contains formatted finding response
	for _, data := range output {
		mimeType := data.GetContentType()

		if strings.EqualFold(mimeType, content_type.LOCAL_FINDING_MODEL) {
			transformedOutput = data
		}
	}

	assert.NotNil(t, transformedOutput)

	var localFinding = local_models.LocalFinding{}
	p, ok := transformedOutput.GetPayload().([]byte)

	assert.True(t, ok)

	err = json.Unmarshal(p, &localFinding)
	assert.NoError(t, err)

	// Assert against local finding transformation
	assert.IsType(t, local_models.LocalFinding{}, localFinding)
	assert.Len(t, localFinding.Findings, 278)

	// Assert Summary
	assert.Equal(t, "sast", localFinding.Summary.Type)
	assert.Equal(t, 4, localFinding.Summary.Artifacts)

	// Assert total findings
	totalCriticalFindings := int(localFinding.Summary.Counts.CountBy.Severity["critical"])
	totalHighFindings := int(localFinding.Summary.Counts.CountBy.Severity["high"])
	totalMediumFindings := int(localFinding.Summary.Counts.CountBy.Severity["medium"])
	totalLowFindings := int(localFinding.Summary.Counts.CountBy.Severity["low"])
	totalFindings := int(localFinding.Summary.Counts.Count)

	assert.Equal(t, 1, totalCriticalFindings)
	assert.Equal(t, 10, totalHighFindings)
	assert.Equal(t, 5, totalMediumFindings)
	assert.Equal(t, 2, totalLowFindings)
	assert.Equal(t, 18, totalFindings)

	// Assert total excluding ignored
	adjustedCriticalFindings := int(localFinding.Summary.Counts.CountByAdjusted.Severity["critical"])
	adjustedHighFindings := int(localFinding.Summary.Counts.CountByAdjusted.Severity["high"])
	adjustedMediumFindings := int(localFinding.Summary.Counts.CountByAdjusted.Severity["medium"])
	adjustedLowFindings := int(localFinding.Summary.Counts.CountByAdjusted.Severity["low"])
	adjustedFindings := int(localFinding.Summary.Counts.CountAdjusted)

	assert.Equal(t, 1, adjustedCriticalFindings)
	assert.Equal(t, 3, adjustedHighFindings)
	assert.Equal(t, 1, adjustedMediumFindings)
	assert.Equal(t, 0, adjustedLowFindings)
	assert.Equal(t, 5, adjustedFindings)

	// Assert total ignored
	ignoredCriticalFindings := int(localFinding.Summary.Counts.CountBySuppressed.Severity["critical"])
	ignoredHighFindings := int(localFinding.Summary.Counts.CountBySuppressed.Severity["high"])
	ignoredMediumFindings := int(localFinding.Summary.Counts.CountBySuppressed.Severity["medium"])
	ignoredLowFindings := int(localFinding.Summary.Counts.CountBySuppressed.Severity["low"])
	ignoredFindings := int(localFinding.Summary.Counts.CountSuppressed)

	assert.Equal(t, 0, ignoredCriticalFindings)
	assert.Equal(t, 2, ignoredHighFindings)
	assert.Equal(t, 1, ignoredMediumFindings)
	assert.Equal(t, 0, ignoredLowFindings)
	assert.Equal(t, 3, ignoredFindings)
}

func Test_DataTransformation_compare_with_Cue(t *testing.T) {
	sarifBytes := loadJsonFile(t, "single-result.json")

	summary := json_schemas.TestSummary{
		Path: "testdata/single-result.json",
		// ...populate other fields as needed...
	}
	summaryBytes, err := json.Marshal(summary)
	assert.NoError(t, err)

	expected, err := TransformToLocalFindingModel(sarifBytes, summaryBytes)
	assert.NoError(t, err)

	actual, err := TransformToLocalFindingModel_nocue(sarifBytes, summaryBytes)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}
