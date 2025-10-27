package ufm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSerializableTestResult(t *testing.T) {
	ctx := context.Background()
	testID := uuid.New()
	createdAt := time.Now().UTC().Truncate(time.Second)
	passFail := testapi.Pass

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mock := mocks.NewMockTestResult(ctrl)
	mock.EXPECT().GetTestID().Return(&testID).AnyTimes()
	mock.EXPECT().GetTestConfiguration().Return(nil).AnyTimes()
	mock.EXPECT().GetCreatedAt().Return(&createdAt).AnyTimes()
	mock.EXPECT().GetTestSubject().Return(testapi.TestSubject{}).AnyTimes()
	mock.EXPECT().GetSubjectLocators().Return(nil).AnyTimes()
	mock.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	mock.EXPECT().GetErrors().Return(nil).AnyTimes()
	mock.EXPECT().GetWarnings().Return(nil).AnyTimes()
	mock.EXPECT().GetPassFail().Return(&passFail).AnyTimes()
	mock.EXPECT().GetOutcomeReason().Return(nil).AnyTimes()
	mock.EXPECT().GetBreachedPolicies().Return(nil).AnyTimes()
	mock.EXPECT().GetEffectiveSummary().Return(nil).AnyTimes()
	mock.EXPECT().GetRawSummary().Return(nil).AnyTimes()
	mock.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).Times(1)

	// Test conversion
	result, err := NewSerializableTestResult(ctx, mock)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify data is preserved
	assert.Equal(t, testID, *result.GetTestID())
	assert.Equal(t, createdAt.Unix(), result.GetCreatedAt().Unix())
	assert.Equal(t, testapi.TestExecutionStatesFinished, result.GetExecutionState())
	assert.Equal(t, passFail, *result.GetPassFail())

	// Test JSON round-trip
	jsonData, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded jsonTestResult
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	// Verify data survives round-trip
	assert.Equal(t, testID, *decoded.GetTestID())
	assert.Equal(t, testapi.TestExecutionStatesFinished, decoded.GetExecutionState())
	assert.Equal(t, passFail, *decoded.GetPassFail())
}

func TestNewSerializableTestResult_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when test result is nil", func(t *testing.T) {
		result, err := NewSerializableTestResult(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("returns error when findings fetch fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := mocks.NewMockTestResult(ctrl)
		mock.EXPECT().Findings(gomock.Any()).Return(nil, false, assert.AnError).Times(1)

		result, err := NewSerializableTestResult(ctx, mock)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}
