package localworkflows

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func setupMockFilterContext(t *testing.T, severityThreshold string) *mocks.MockInvocationContext {
	t.Helper()

	// setup
	logger := zerolog.Logger{}
	config := configuration.New()
	config.Set(configuration.FLAG_SEVERITY_THRESHOLD, severityThreshold)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	// setup invocation context
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	return invocationContextMock
}

func getRandomWorkflowData() workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, "randomtype"),
		"application/random",
		[]byte{},
	)
}

func getFindingsInputData(t *testing.T) workflow.Data {
	t.Helper()
	sarifBytes := loadJsonFile(t, "sarif-juice-shop.json")
	summaryBytes := loadJsonFile(t, "juice-shop-summary.json")

	findings, err := TransformSarifToLocalFindingModel(sarifBytes, summaryBytes)
	assert.NoError(t, err)

	findingsBytes, err := json.Marshal(findings)
	assert.NoError(t, err)
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, FilterFindingsWorkflowName),
		content_type.LOCAL_FINDING_MODEL,
		findingsBytes,
	)
}

func getFindingsInputDataBroken() workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, FilterFindingsWorkflowName),
		content_type.LOCAL_FINDING_MODEL,
		[]byte("not json"),
	)
}

func TestFilterWorkflowRegistration(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)
	err := InitFilterFindingsWorkflow(engine)
	assert.NoError(t, err)
	entry, ok := engine.GetWorkflow(WORKFLOWID_FILTER_FINDINGS)
	assert.True(t, ok)
	assert.NotNil(t, entry)
}

func TestFilterFindingsEntryPoint(t *testing.T) {
	t.Run("with invalid payload type", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "low")
		input := []workflow.Data{workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, FilterFindingsWorkflowName),
			content_type.LOCAL_FINDING_MODEL, nil)}
		output, err := filterFindingsEntryPoint(ctx, input)
		assert.NoError(t, err)
		assert.Equal(t, input[0], output[0])
	})

	t.Run("with non json payload type", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "low")
		input := []workflow.Data{getFindingsInputDataBroken()}
		output, err := filterFindingsEntryPoint(ctx, input)
		assert.NoError(t, err)
		assert.Equal(t, input[0], output[0])
	})

	t.Run("with invalid severity threshold", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "invalid")
		var findings local_models.LocalFinding = local_models.LocalFinding{}
		findingsBytes, err := json.Marshal(findings)
		assert.NoError(t, err)
		input := []workflow.Data{workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, FilterFindingsWorkflowName),
			content_type.LOCAL_FINDING_MODEL,
			findingsBytes,
		)}
		output, err := filterFindingsEntryPoint(ctx, input)
		assert.NoError(t, err)
		assert.Equal(t, input, output)
	})

	t.Run("filters findings with threshold set to high", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "hIgH")
		randomInputData := getRandomWorkflowData()
		findingsData := getFindingsInputData(t)
		input := []workflow.Data{findingsData, randomInputData}
		output, err := filterFindingsEntryPoint(ctx, input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), len(output))
		var filteredFindings local_models.LocalFinding
		err = json.Unmarshal(output[0].GetPayload().([]byte), &filteredFindings) //nolint:errcheck //in this test, the type is clear
		assert.NoError(t, err)
		for _, finding := range filteredFindings.Findings {
			severity := string(finding.Attributes.Rating.Severity.Value)
			assert.True(t, severity == "high" || severity == "critical", "Unexpected severity: %s", severity)
		}
		assert.Equal(t, randomInputData, output[1])
	})

	t.Run("pass input data through when severity threshold is not set", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "")
		randomInputData := getRandomWorkflowData()
		randomInputData2 := getRandomWorkflowData()
		findingsData := getFindingsInputData(t)
		input := []workflow.Data{randomInputData, findingsData, randomInputData2}
		output, err := filterFindingsEntryPoint(ctx, input)
		assert.NoError(t, err)
		assert.Equal(t, input, output)
	})
	t.Run("updates findings summary with filtered totals", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "high")
		sarifBytes := loadJsonFile(t, "sarif-juice-shop.json")
		summaryBytes := loadJsonFile(t, "juice-shop-summary.json")
		findingsInput, err := TransformSarifToLocalFindingModel(sarifBytes, summaryBytes)
		assert.NoError(t, err)
		findingsBytes, err := json.Marshal(findingsInput)
		assert.NoError(t, err)
		input := []workflow.Data{workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS, FilterFindingsWorkflowName),
			content_type.LOCAL_FINDING_MODEL,
			findingsBytes,
		)}
		output, err := filterFindingsEntryPoint(ctx, input)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(output))
		var filteredFindings local_models.LocalFinding
		err = json.Unmarshal(output[0].GetPayload().([]byte), &filteredFindings) //nolint:errcheck //in this test, the type is clear
		assert.NoError(t, err)

		expectedCounts := local_models.NewFindingsCounts()
		expectedCounts.Count = 25
		expectedCounts.CountAdjusted = 25
		expectedCounts.CountKeyOrderAsc = local_models.TypesFindingCounts_CountKeyOrderAsc{
			Severity: json_schemas.DEFAULT_SEVERITIES,
		}
		expectedCounts.CountBy = local_models.TypesFindingCounts_CountBy{
			Severity: map[string]uint32{
				"high": 25,
			},
		}
		expectedCounts.CountByAdjusted = local_models.TypesFindingCounts_CountByAdjusted{
			Severity: map[string]uint32{
				"high": 25,
			},
		}
		assert.Equal(t, expectedCounts, filteredFindings.Summary.Counts)
	})
}
