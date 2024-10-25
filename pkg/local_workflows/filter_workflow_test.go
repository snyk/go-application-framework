package localworkflows

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
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

	t.Run("filters findings with treshold set to high", func(t *testing.T) {
		ctx := setupMockFilterContext(t, "high")
		sarifBytes := loadJsonFile(t, "sarif-juice-shop.json")
		summaryBytes := loadJsonFile(t, "juice-shop-summary.json")
		findings, err := TransformToLocalFindingModel(sarifBytes, summaryBytes)
		assert.NoError(t, err)
		findingsBytes, err := json.Marshal(findings)
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
		err = json.Unmarshal(output[0].GetPayload().([]byte), &filteredFindings)

		assert.NoError(t, err)
		for _, finding := range filteredFindings.Findings {
			severity := string(finding.Attributes.Rating.Severity.Value)
			assert.True(t, severity == "high" || severity == "critical", "Unexpected severity: %s", severity)
		}
	})
}
