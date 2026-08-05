package localworkflows

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func setupDeltaMockContext(t *testing.T, changedLinesJSON string) *mocks.MockInvocationContext {
	t.Helper()
	logger := zerolog.Nop()
	config := configuration.New()
	if changedLinesJSON != "" {
		config.Set(configuration.FLAG_CHANGED_LINES, changedLinesJSON)
	}
	ctrl := gomock.NewController(t)
	invCtx := mocks.NewMockInvocationContext(ctrl)
	invCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	return invCtx
}

func makeFindingsData(t *testing.T, findings local_models.LocalFinding) workflow.Data {
	t.Helper()
	b, err := json.Marshal(findings)
	require.NoError(t, err)
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS_DELTA, DeltaFilterFindingsWorkflowName),
		content_type.LOCAL_FINDING_MODEL,
		b,
	)
}

func buildLocalFinding(t *testing.T) local_models.LocalFinding {
	t.Helper()
	sarifBytes := loadJsonFile(t, "sarif-juice-shop.json")
	summaryBytes := loadJsonFile(t, "juice-shop-summary.json")
	findings, err := TransformSarifToLocalFindingModel(sarifBytes, summaryBytes)
	require.NoError(t, err)
	return findings
}

func TestDeltaFilterWorkflowRegistration(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)
	err := InitDeltaFilterFindingsWorkflow(engine)
	assert.NoError(t, err)
	entry, ok := engine.GetWorkflow(WORKFLOWID_FILTER_FINDINGS_DELTA)
	assert.True(t, ok)
	assert.NotNil(t, entry)
}

func TestDeltaFilterWorkflow_NoFlagPassThrough(t *testing.T) {
	// no changed-lines flag → all findings returned unchanged
	invCtx := setupDeltaMockContext(t, "")
	findingsModel := buildLocalFinding(t)
	total := len(findingsModel.Findings)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	output, err := deltaFilterFindingsEntryPoint(invCtx, input)
	require.NoError(t, err)
	assert.Equal(t, input, output) // must be same slice, no copying
	assert.Len(t, output, 1)

	// verify finding count unchanged
	var out local_models.LocalFinding
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok, "expected []byte payload")
	require.NoError(t, json.Unmarshal(payload, &out))
	assert.Equal(t, total, len(out.Findings))
}

func TestDeltaFilterWorkflow_FilterByLine(t *testing.T) {
	// juice-shop finding 0: routes/likeProductReviews.ts line 18
	// request only line 18 of that file → only findings on that line survive
	invCtx := setupDeltaMockContext(t, `{"version":1,"files":{"routes/likeProductReviews.ts":[{"start":18,"end":18}]}}`)
	findingsModel := buildLocalFinding(t)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	output, err := deltaFilterFindingsEntryPoint(invCtx, input)
	require.NoError(t, err)
	require.Len(t, output, 1)

	var out local_models.LocalFinding
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok, "expected []byte payload")
	require.NoError(t, json.Unmarshal(payload, &out))
	assert.True(t, len(out.Findings) > 0, "expected at least one finding on line 18")
	assert.True(t, len(out.Findings) < len(findingsModel.Findings), "expected fewer findings after delta filter")
}

func TestDeltaFilterWorkflow_AllSentinel(t *testing.T) {
	// "all" sentinel → every finding in that file passes
	invCtx := setupDeltaMockContext(t, `{"version":1,"files":{"routes/likeProductReviews.ts":"all"}}`)
	findingsModel := buildLocalFinding(t)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	output, err := deltaFilterFindingsEntryPoint(invCtx, input)
	require.NoError(t, err)
	require.Len(t, output, 1)

	var out local_models.LocalFinding
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok, "expected []byte payload")
	require.NoError(t, json.Unmarshal(payload, &out))
	assert.True(t, len(out.Findings) > 0)
}

func TestDeltaFilterWorkflow_FileNotInScope(t *testing.T) {
	// no matching file → zero findings
	invCtx := setupDeltaMockContext(t, `{"version":1,"files":{"does/not/exist.ts":[{"start":1,"end":10}]}}`)
	findingsModel := buildLocalFinding(t)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	output, err := deltaFilterFindingsEntryPoint(invCtx, input)
	require.NoError(t, err)
	require.Len(t, output, 1)

	var out local_models.LocalFinding
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok, "expected []byte payload")
	require.NoError(t, json.Unmarshal(payload, &out))
	assert.Len(t, out.Findings, 0)
}

func TestDeltaFilterWorkflow_MalformedInputFailsClosed(t *testing.T) {
	invCtx := setupDeltaMockContext(t, `{not valid json`)
	findingsModel := buildLocalFinding(t)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	_, err := deltaFilterFindingsEntryPoint(invCtx, input)
	assert.Error(t, err)
}

func TestDeltaFilterWorkflow_EmptyFilesFailsClosed(t *testing.T) {
	invCtx := setupDeltaMockContext(t, `{"version":1,"files":{}}`)
	findingsModel := buildLocalFinding(t)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	_, err := deltaFilterFindingsEntryPoint(invCtx, input)
	assert.Error(t, err)
}

func TestDeltaFilterWorkflow_NonFindingDataPassThrough(t *testing.T) {
	invCtx := setupDeltaMockContext(t, `{"version":1,"files":{"a.py":[{"start":1,"end":10}]}}`)
	randomData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_FILTER_FINDINGS_DELTA, "random"),
		"application/random",
		[]byte("random"),
	)
	output, err := deltaFilterFindingsEntryPoint(invCtx, []workflow.Data{randomData})
	require.NoError(t, err)
	require.Len(t, output, 1)
	assert.Equal(t, randomData, output[0])
}

func TestDeltaFilterWorkflow_SummaryUpdatedAfterFilter(t *testing.T) {
	// After filtering, the summary counts should reflect remaining findings
	invCtx := setupDeltaMockContext(t, `{"version":1,"files":{"routes/likeProductReviews.ts":[{"start":18,"end":18}]}}`)
	findingsModel := buildLocalFinding(t)
	input := []workflow.Data{makeFindingsData(t, findingsModel)}

	output, err := deltaFilterFindingsEntryPoint(invCtx, input)
	require.NoError(t, err)
	require.Len(t, output, 1)

	var out local_models.LocalFinding
	payload, ok := output[0].GetPayload().([]byte)
	require.True(t, ok, "expected []byte payload")
	require.NoError(t, json.Unmarshal(payload, &out))

	// sum of summary counts should equal number of findings
	var totalFromSummary uint32
	for _, v := range out.Summary.Counts.CountBy.Severity {
		totalFromSummary += v
	}
	assert.Equal(t, uint32(len(out.Findings)), totalFromSummary, "summary counts should match filtered findings")
}
