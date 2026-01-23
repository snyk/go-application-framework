package ufm

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_CreateAndRetrieveDataFromUFM(t *testing.T) {
	testID := uuid.New()
	passFail := testapi.Pass
	ctlr := gomock.NewController(t)
	singleResult := mocks.NewMockTestResult(ctlr)

	findings := []testapi.FindingData{
		{
			Id: &testID,
			Attributes: &testapi.FindingAttributes{
				Title: "Test finding",
			},
		},
	}
	// Set up expectations for all TestResult interface methods that will be called during serialization
	singleResult.EXPECT().GetTestID().Return(&testID).AnyTimes()
	singleResult.EXPECT().GetTestConfiguration().Return(nil).AnyTimes()
	singleResult.EXPECT().GetCreatedAt().Return(nil).AnyTimes()
	singleResult.EXPECT().GetTestSubject().Return(nil).AnyTimes()
	singleResult.EXPECT().GetSubjectLocators().Return(nil).AnyTimes()
	singleResult.EXPECT().GetTestResources().Return(nil).AnyTimes()
	singleResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	singleResult.EXPECT().GetErrors().Return(nil).AnyTimes()
	singleResult.EXPECT().GetWarnings().Return(nil).AnyTimes()
	singleResult.EXPECT().GetPassFail().Return(&passFail).AnyTimes()
	singleResult.EXPECT().GetOutcomeReason().Return(nil).AnyTimes()
	singleResult.EXPECT().GetBreachedPolicies().Return(nil).AnyTimes()
	singleResult.EXPECT().GetEffectiveSummary().Return(nil).AnyTimes()
	singleResult.EXPECT().GetRawSummary().Return(nil).AnyTimes()
	singleResult.EXPECT().GetTestFacts().Return(nil).AnyTimes()
	singleResult.EXPECT().GetMetadata().Return(nil).AnyTimes()
	singleResult.EXPECT().Findings(gomock.Any()).Return(findings, true, nil).AnyTimes()

	results := []testapi.TestResult{singleResult}

	// Create workflow data (this serializes to JSON bytes)
	data := CreateWorkflowDataFromTestResults(workflow.NewWorkflowIdentifier("myflow`"), results)
	assert.NotNil(t, data)

	// Retrieve and deserialize the results
	tmp := GetTestResultsFromWorkflowData(data)
	assert.NotNil(t, tmp)
	assert.Equal(t, len(results), len(tmp))

	// Verify the deserialized data matches
	assert.Equal(t, testID, *tmp[0].GetTestID())
	assert.Equal(t, testapi.TestExecutionStatesFinished, tmp[0].GetExecutionState())
	assert.Equal(t, passFail, *tmp[0].GetPassFail())

	actualFindings, complete, err := tmp[0].Findings(context.Background())
	assert.NoError(t, err)
	assert.True(t, complete)
	assert.Equal(t, findings, actualFindings)
}
