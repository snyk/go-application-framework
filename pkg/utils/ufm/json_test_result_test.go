package ufm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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
	mock.EXPECT().GetMetadata().Return(nil).AnyTimes()
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

func TestNewSerializableTestResultFromBytes_OldFormat(t *testing.T) {
	// Test that old format (with inline problems) still works
	jsonData := `[{
		"testId": "550e8400-e29b-41d4-a716-446655440001",
		"executionState": "finished",
		"findingsComplete": true,
		"findings": [
			{
				"id": "550e8400-e29b-41d4-a716-446655440002",
				"attributes": {
					"finding_type": "sca",
					"key": "key-1",
					"title": "Test Finding 1",
					"description": "Test",
					"cause_of_failure": false,
					"problems": [
						{"id":"SNYK-JS-LODASH-590103","source":"snyk_vuln","package_name":"lodash"}
					],
					"rating": {"severity": "high"},
					"risk": {"score": 500},
					"evidence": [],
					"locations": []
				}
			},
			{
				"id": "550e8400-e29b-41d4-a716-446655440003",
				"attributes": {
					"finding_type": "sca",
					"key": "key-2",
					"title": "Test Finding 2",
					"description": "Test",
					"cause_of_failure": false,
					"problems": [
						{"id":"SNYK-JS-LODASH-590103","source":"snyk_vuln","package_name":"lodash"}
					],
					"rating": {"severity": "high"},
					"risk": {"score": 500},
					"evidence": [],
					"locations": []
				}
			}
		]
	}]`

	results, err := NewSerializableTestResultFromBytes([]byte(jsonData))
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Get findings
	findings, complete, err := results[0].Findings(context.Background())
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, findings, 2)

	// Both findings should have their problem
	assert.Len(t, findings[0].Attributes.Problems, 1)
	assert.Len(t, findings[1].Attributes.Problems, 1)

	// Both should have the same problem ID
	assert.Equal(t, "SNYK-JS-LODASH-590103", findings[0].Attributes.Problems[0].GetID())
	assert.Equal(t, "SNYK-JS-LODASH-590103", findings[1].Attributes.Problems[0].GetID())
}

func TestOptimizedWireFormat_RoundTrip(t *testing.T) {
	ctx := context.Background()

	// Create test result with duplicate problems
	findingID1 := uuid.New()
	findingID2 := uuid.New()

	sharedProblemJSON := `{"id":"SNYK-JS-LODASH-590103","source":"snyk_vuln","package_name":"lodash"}`
	var problem1, problem2 testapi.Problem
	require.NoError(t, json.Unmarshal([]byte(sharedProblemJSON), &problem1))
	require.NoError(t, json.Unmarshal([]byte(sharedProblemJSON), &problem2))

	findings := []testapi.FindingData{
		{
			Id: &findingID1,
			Attributes: &testapi.FindingAttributes{
				FindingType:    testapi.FindingTypeSca,
				Key:            "key-1",
				Title:          "Finding 1",
				Description:    "Test",
				CauseOfFailure: false,
				Problems:       []testapi.Problem{problem1},
				Evidence:       []testapi.Evidence{},
				Locations:      []testapi.FindingLocation{},
			},
		},
		{
			Id: &findingID2,
			Attributes: &testapi.FindingAttributes{
				FindingType:    testapi.FindingTypeSca,
				Key:            "key-2",
				Title:          "Finding 2",
				Description:    "Test",
				CauseOfFailure: false,
				Problems:       []testapi.Problem{problem2}, // Same problem
				Evidence:       []testapi.Evidence{},
				Locations:      []testapi.FindingLocation{},
			},
		},
	}

	// Use the builder to create optimized format
	problemStore, problemRefs, optimizedFindings := BuildOptimizedFormat(findings)

	original := &jsonTestResult{
		TestID:           func() *uuid.UUID { id := uuid.New(); return &id }(),
		ExecutionState:   testapi.TestExecutionStatesFinished,
		FindingsComplete: true,
		ProblemStore:     problemStore,
		ProblemRefs:      problemRefs,
		FindingsData:     optimizedFindings,
		fullFindings:     findings,
	}

	// Marshal to JSON (should use optimized format)
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Verify JSON contains problemStore and _problemRefs
	var wireFormat map[string]interface{}
	require.NoError(t, json.Unmarshal(jsonData, &wireFormat))
	assert.Contains(t, wireFormat, "problemStore", "Should have problemStore in wire format")
	assert.Contains(t, wireFormat, "_problemRefs", "Should have _problemRefs in wire format")

	// Verify problemStore has the deduplicated problem
	problemStoreRaw, ok := wireFormat["problemStore"].(map[string]interface{})
	require.True(t, ok)
	assert.Len(t, problemStoreRaw, 1, "Should have exactly 1 deduplicated problem")
	assert.Contains(t, problemStoreRaw, "SNYK-JS-LODASH-590103")

	// Verify findings don't have inline problems
	findingsRaw, ok := wireFormat["findings"].([]interface{})
	require.True(t, ok)
	require.Len(t, findingsRaw, 2)

	// Unmarshal back
	var decoded jsonTestResult
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	// Reconstruct findings from optimized format
	err = ReconstructFindings(&decoded)
	require.NoError(t, err)

	// Verify findings are reconstructed correctly
	decodedFindings, complete, err := decoded.Findings(ctx)
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, decodedFindings, 2)

	// Both findings should have their problems reconstructed
	assert.Len(t, decodedFindings[0].Attributes.Problems, 1)
	assert.Len(t, decodedFindings[1].Attributes.Problems, 1)
	assert.Equal(t, "SNYK-JS-LODASH-590103", decodedFindings[0].Attributes.Problems[0].GetID())
	assert.Equal(t, "SNYK-JS-LODASH-590103", decodedFindings[1].Attributes.Problems[0].GetID())
}

func TestOptimizedWireFormat_BackwardCompatibility(t *testing.T) {
	ctx := context.Background()

	// Old format JSON (without problemStore)
	oldFormatJSON := `{
		"testId": "550e8400-e29b-41d4-a716-446655440001",
		"executionState": "finished",
		"findingsComplete": true,
		"findings": [
			{
				"id": "550e8400-e29b-41d4-a716-446655440002",
				"attributes": {
					"finding_type": "sca",
					"key": "key-1",
					"title": "Test Finding",
					"description": "Test",
					"cause_of_failure": false,
					"problems": [
						{"id":"CVE-2021-1234","source":"cve"}
					],
					"rating": {"severity": "high"},
					"risk": {"score": 500},
					"evidence": [],
					"locations": []
				}
			}
		]
	}`

	// Should still unmarshal correctly
	var decoded jsonTestResult
	err := json.Unmarshal([]byte(oldFormatJSON), &decoded)
	require.NoError(t, err)

	// Verify finding has its problem
	findings, complete, err := decoded.Findings(ctx)
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, findings, 1)
	assert.Len(t, findings[0].Attributes.Problems, 1)
	assert.Equal(t, "CVE-2021-1234", findings[0].Attributes.Problems[0].GetID())
}

func TestOptimizedWireFormat_MixedProblems(t *testing.T) {
	ctx := context.Background()
	findingID1 := uuid.New()
	findingID2 := uuid.New()

	// Create problems - some with IDs, some without
	problemWithID := `{"id":"SNYK-JS-TEST-123","source":"snyk_vuln"}`
	problemWithoutID := `{"source":"cwe","title":"CWE-89"}`

	var prob1, prob2, prob3 testapi.Problem
	require.NoError(t, json.Unmarshal([]byte(problemWithID), &prob1))
	require.NoError(t, json.Unmarshal([]byte(problemWithoutID), &prob2))
	require.NoError(t, json.Unmarshal([]byte(problemWithID), &prob3))

	findings := []testapi.FindingData{
		{
			Id: &findingID1,
			Attributes: &testapi.FindingAttributes{
				FindingType:    testapi.FindingTypeSca,
				Key:            "key-1",
				Title:          "Finding 1",
				CauseOfFailure: false,
				Problems:       []testapi.Problem{prob1, prob2},
				Evidence:       []testapi.Evidence{},
				Locations:      []testapi.FindingLocation{},
			},
		},
		{
			Id: &findingID2,
			Attributes: &testapi.FindingAttributes{
				FindingType:    testapi.FindingTypeSca,
				Key:            "key-2",
				Title:          "Finding 2",
				CauseOfFailure: false,
				Problems:       []testapi.Problem{prob3}, // Same as prob1
				Evidence:       []testapi.Evidence{},
				Locations:      []testapi.FindingLocation{},
			},
		},
	}

	// Use the builder to create optimized format
	problemStore, problemRefs, optimizedFindings := BuildOptimizedFormat(findings)

	original := &jsonTestResult{
		TestID:           func() *uuid.UUID { id := uuid.New(); return &id }(),
		ExecutionState:   testapi.TestExecutionStatesFinished,
		FindingsComplete: true,
		ProblemStore:     problemStore,
		ProblemRefs:      problemRefs,
		FindingsData:     optimizedFindings,
		fullFindings:     findings,
	}

	// Marshal and unmarshal
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded jsonTestResult
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	// Reconstruct findings from optimized format
	err = ReconstructFindings(&decoded)
	require.NoError(t, err)

	// Verify all problems are reconstructed
	decodedFindings2, _, err2 := decoded.Findings(ctx)
	require.NoError(t, err2)
	require.Len(t, decodedFindings2, 2)

	assert.Len(t, decodedFindings2[0].Attributes.Problems, 2)
	assert.Equal(t, "SNYK-JS-TEST-123", decodedFindings2[0].Attributes.Problems[0].GetID())
	assert.Equal(t, "", decodedFindings2[0].Attributes.Problems[1].GetID()) // Problem without ID

	assert.Len(t, decodedFindings2[1].Attributes.Problems, 1)
	assert.Equal(t, "SNYK-JS-TEST-123", decodedFindings2[1].Attributes.Problems[0].GetID())
}

func TestOptimizedWireFormat_MemoryCleanup(t *testing.T) {
	ctx := context.Background()
	findingID := uuid.New()

	problemJSON := `{"id":"SNYK-JS-LODASH-590103","source":"snyk_vuln","package_name":"lodash"}`
	var problem testapi.Problem
	require.NoError(t, json.Unmarshal([]byte(problemJSON), &problem))

	findings := []testapi.FindingData{
		{
			Id: &findingID,
			Attributes: &testapi.FindingAttributes{
				FindingType:    testapi.FindingTypeSca,
				Key:            "key-1",
				Title:          "Finding 1",
				CauseOfFailure: false,
				Problems:       []testapi.Problem{problem},
				Evidence:       []testapi.Evidence{},
				Locations:      []testapi.FindingLocation{},
			},
		},
	}

	problemStore, problemRefs, optimizedFindings := BuildOptimizedFormat(findings)

	result := &jsonTestResult{
		TestID:           func() *uuid.UUID { id := uuid.New(); return &id }(),
		ExecutionState:   testapi.TestExecutionStatesFinished,
		FindingsComplete: true,
		ProblemStore:     problemStore,
		ProblemRefs:      problemRefs,
		FindingsData:     optimizedFindings,
		fullFindings:     findings,
	}

	// Marshal and unmarshal
	jsonData, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded jsonTestResult
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	// Before reconstruction - optimized data should be present
	assert.NotNil(t, decoded.ProblemStore, "ProblemStore should exist before reconstruction")
	assert.NotNil(t, decoded.ProblemRefs, "ProblemRefs should exist before reconstruction")
	assert.NotNil(t, decoded.FindingsData, "FindingsData should exist before reconstruction")
	assert.Nil(t, decoded.fullFindings, "fullFindings should be nil before reconstruction")

	// Reconstruct
	err = ReconstructFindings(&decoded)
	require.NoError(t, err)

	// After reconstruction - optimized data should be cleared to free memory
	assert.Nil(t, decoded.ProblemStore, "ProblemStore should be cleared after reconstruction")
	assert.Nil(t, decoded.ProblemRefs, "ProblemRefs should be cleared after reconstruction")
	assert.Nil(t, decoded.FindingsData, "FindingsData should be cleared after reconstruction")
	assert.NotNil(t, decoded.fullFindings, "fullFindings should exist after reconstruction")

	// Verify findings are still accessible
	decodedFindings, complete, err := decoded.Findings(ctx)
	require.NoError(t, err)
	require.True(t, complete)
	require.Len(t, decodedFindings, 1)
	assert.Len(t, decodedFindings[0].Attributes.Problems, 1)
	assert.Equal(t, "SNYK-JS-LODASH-590103", decodedFindings[0].Attributes.Problems[0].GetID())
}

func Test_Findings_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	testResultsPath, err := filepath.Abs("../../../internal/presenters/testdata/ufm/webgoat.ignore.testresult.json")
	require.NoError(t, err)
	testResultsData, err := os.ReadFile(testResultsPath)
	require.NoError(t, err)

	testResults, err := NewSerializableTestResultFromBytes(testResultsData)
	require.NoError(t, err)
	require.Len(t, testResults, 1)

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			findings, complete, err := testResults[0].Findings(ctx)
			require.NoError(t, err)
			require.True(t, complete)
			require.Len(t, findings, 91)
		}()
	}
	wg.Wait()
}
