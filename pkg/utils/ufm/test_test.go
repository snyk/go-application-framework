package ufm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// stubResult builds a minimal serializable test result carrying the given metadata.
func stubResult(t *testing.T, metadata map[string]interface{}) testapi.TestResult {
	t.Helper()

	testID := uuid.New()
	result := mocks.NewMockTestResult(gomock.NewController(t))
	result.EXPECT().Findings(gomock.Any()).Return(nil, true, nil).AnyTimes()
	result.EXPECT().GetTestID().Return(&testID).AnyTimes()
	result.EXPECT().GetTestConfiguration().Return(nil).AnyTimes()
	result.EXPECT().GetCreatedAt().Return(nil).AnyTimes()
	result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	result.EXPECT().GetErrors().Return(nil).AnyTimes()
	result.EXPECT().GetWarnings().Return(nil).AnyTimes()
	result.EXPECT().GetPassFail().Return(nil).AnyTimes()
	result.EXPECT().GetOutcomeReason().Return(nil).AnyTimes()
	result.EXPECT().GetEffectiveSummary().Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultTestSubject).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultSubjectLocators).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultBreachedPolicies).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultRawSummary).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultTestFacts).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultMetadata).Return(metadata).AnyTimes()
	result.EXPECT().Get(testapi.TestResultComponents).Return(nil).AnyTimes()

	return result
}

func Test_Test_AssetLink(t *testing.T) {
	assert.Equal(t, "https://app.snyk.io/asset/1",
		Test{Metadata: map[string]interface{}{"asset": "https://app.snyk.io/asset/1"}}.AssetLink())
	assert.Empty(t, Test{Metadata: map[string]interface{}{"report-url": "https://app.snyk.io/report"}}.AssetLink())
	assert.Empty(t, Test{}.AssetLink(), "a test need not cover an asset")
	assert.Empty(t, Test{Metadata: map[string]interface{}{"asset": 42}}.AssetLink(), "a non-string asset is not a link")
}

func Test_CreateWorkflowDataFromTest_RoundTripsTestMetadata(t *testing.T) {
	// The asset belongs to the test, not to any one of its results.
	metadata := map[string]interface{}{"asset": "https://app.snyk.io/asset/1"}
	results := []testapi.TestResult{stubResult(t, nil), stubResult(t, nil)}

	data := CreateWorkflowDataFromTest(workflow.NewWorkflowIdentifier("myflow"), metadata, results)
	require.NotNil(t, data)

	test := GetTestFromWorkflowData(data)
	require.NotNil(t, test)
	assert.Equal(t, "https://app.snyk.io/asset/1", test.AssetLink())
	assert.Len(t, test.Results, 2, "the results are reported alongside the test that produced them")

	// The results themselves carry no copy of it.
	for _, result := range test.Results {
		assert.Nil(t, result.GetMetadataValue("asset"))
	}
}

func Test_CreateWorkflowDataFromTest_WithoutMetadata(t *testing.T) {
	data := CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("myflow"), []testapi.TestResult{stubResult(t, nil)})
	require.NotNil(t, data)

	test := GetTestFromWorkflowData(data)
	require.NotNil(t, test)
	assert.Empty(t, test.AssetLink())
	assert.Len(t, test.Results, 1)
}

func Test_CreateWorkflowDataFromTest_NoResults(t *testing.T) {
	assert.Nil(t, CreateWorkflowDataFromTest(workflow.NewWorkflowIdentifier("myflow"), nil, nil))
}

func Test_NewSerializableTestFromBytes_ReadsBothWireFormats(t *testing.T) {
	serializable, err := newSerializableTestResult(context.Background(), stubResult(t, map[string]interface{}{"project-name": "a"}))
	require.NoError(t, err)

	t.Run("a test and its results", func(t *testing.T) {
		payload, marshalErr := json.Marshal(jsonTest{
			Metadata: map[string]interface{}{"asset": "https://app.snyk.io/asset/1"},
			Results:  []*jsonTestResult{serializable},
		})
		require.NoError(t, marshalErr)

		test, testErr := NewSerializableTestFromBytes(payload)
		require.NoError(t, testErr)
		assert.Equal(t, "https://app.snyk.io/asset/1", test.AssetLink())
		assert.Len(t, test.Results, 1)
	})

	t.Run("a bare array of results, as written before tests carried metadata", func(t *testing.T) {
		payload, marshalErr := json.Marshal([]*jsonTestResult{serializable})
		require.NoError(t, marshalErr)

		test, testErr := NewSerializableTestFromBytes(payload)
		require.NoError(t, testErr)
		assert.Empty(t, test.AssetLink())
		require.Len(t, test.Results, 1)
		assert.Equal(t, "a", test.Results[0].GetMetadataValue("project-name"))
	})

	t.Run("malformed", func(t *testing.T) {
		_, testErr := NewSerializableTestFromBytes([]byte("not json"))
		assert.Error(t, testErr)
	})
}
