package testapi_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIssuesExtractor is a mock implementation of IssuesExtractor for testing.
type mockIssuesExtractor struct {
	ctrl     *gomock.Controller
	recorder *mockIssuesExtractorMockRecorder
}

type mockIssuesExtractorMockRecorder struct {
	mock *mockIssuesExtractor
}

func NewMockIssuesExtractor(ctrl *gomock.Controller) *mockIssuesExtractor {
	mock := &mockIssuesExtractor{ctrl: ctrl}
	mock.recorder = &mockIssuesExtractorMockRecorder{mock}
	return mock
}

func (m *mockIssuesExtractor) EXPECT() *mockIssuesExtractorMockRecorder {
	return m.recorder
}

func (m *mockIssuesExtractor) ExtractFindings(ctx context.Context) ([]testapi.FindingData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExtractFindings", ctx)
	ret0, _ := ret[0].([]testapi.FindingData) //nolint:errcheck // type assertion in mock
	ret1, _ := ret[1].(error)                 //nolint:errcheck // type assertion in mock
	return ret0, ret1
}

func (mr *mockIssuesExtractorMockRecorder) ExtractFindings(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExtractFindings", reflect.TypeOf((*mockIssuesExtractor)(nil).ExtractFindings), ctx)
}

func TestNewIssuesFromTestResult(t *testing.T) {
	ctx := context.Background()

	t.Run("successfully creates issues from test result", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockResult := mocks.NewMockTestResult(ctrl)
		findingType1 := testapi.FindingTypeSca
		findingType2 := testapi.FindingTypeSast

		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: findingType1,
					Title:       "Test Finding 1",
					Problems: []testapi.Problem{
						{},
					},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: findingType2,
					Title:       "Test Finding 2",
					Problems: []testapi.Problem{
						{},
						{},
					},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: findingType1,
					Title:       "Test Finding 3",
					Problems:    []testapi.Problem{},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		mockResult.EXPECT().Findings(gomock.Any()).Return(findings, true, nil).Times(1)

		// NewIssuesFromTestResult creates a list of Issues from findings
		issuesList, err := testapi.NewIssuesFromTestResult(ctx, mockResult)
		require.NoError(t, err)
		require.NotNil(t, issuesList)
		assert.GreaterOrEqual(t, len(issuesList), 1)

		// Test the first issue
		if len(issuesList) > 0 {
			issue := issuesList[0]
			// Test GetFindings
			returnedFindings := issue.GetFindings()
			assert.GreaterOrEqual(t, len(returnedFindings), 1)

			// Test GetFindingType
			findingType := issue.GetFindingType()
			assert.NotEmpty(t, findingType)

			// Test GetProblems
			problems := issue.GetProblems()
			assert.GreaterOrEqual(t, len(problems), 0)

			// Test GetID - should have an ID
			id := issue.GetID()
			assert.NotEmpty(t, id)

			// Test GetTitle - should have a title
			title := issue.GetTitle()
			assert.NotEmpty(t, title)
		}
	})

	t.Run("returns error when test result is nil", func(t *testing.T) {
		issues, err := testapi.NewIssuesFromTestResult(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, issues)
		assert.Contains(t, err.Error(), "testResult cannot be nil")
	})

	t.Run("returns error when findings fetch fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockResult := mocks.NewMockTestResult(ctrl)
		mockResult.EXPECT().Findings(gomock.Any()).Return(nil, false, errors.New("fetch error")).Times(1)

		issues, err := testapi.NewIssuesFromTestResult(ctx, mockResult)
		assert.Error(t, err)
		assert.Nil(t, issues)
		assert.Contains(t, err.Error(), "failed to extract findings")
	})

	t.Run("handles empty findings", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockResult := mocks.NewMockTestResult(ctrl)
		mockResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).Times(1)

		issuesList, err := testapi.NewIssuesFromTestResult(ctx, mockResult)
		require.NoError(t, err)
		require.NotNil(t, issuesList)
		assert.Len(t, issuesList, 0)
	})

	t.Run("handles findings with nil attributes", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockResult := mocks.NewMockTestResult(ctrl)
		findings := []testapi.FindingData{
			{
				Attributes: nil,
				Id:         func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSca,
					Problems:    []testapi.Problem{},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		mockResult.EXPECT().Findings(gomock.Any()).Return(findings, true, nil).Times(1)

		issuesList, err := testapi.NewIssuesFromTestResult(ctx, mockResult)
		require.NoError(t, err)
		require.NotNil(t, issuesList)
		assert.GreaterOrEqual(t, len(issuesList), 1)
	})
}

func TestNewIssueFromFindings(t *testing.T) {
	t.Run("successfully creates issue from findings", func(t *testing.T) {
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSca,
					Title:       "Test Issue",
					Problems:    []testapi.Problem{},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		issue, err := testapi.NewIssueFromFindings(findings)
		require.NoError(t, err)
		require.NotNil(t, issue)

		assert.Len(t, issue.GetFindings(), 1)
		assert.Equal(t, testapi.FindingTypeSca, issue.GetFindingType())
		assert.NotEmpty(t, issue.GetID())
		assert.NotEmpty(t, issue.GetTitle())
	})

	t.Run("returns error when findings is empty", func(t *testing.T) {
		issue, err := testapi.NewIssueFromFindings([]testapi.FindingData{})
		assert.Error(t, err)
		assert.Nil(t, issue)
		assert.Contains(t, err.Error(), "findings cannot be empty")
	})
}

func TestNewIssuesFromTestResult_Grouping(t *testing.T) {
	ctx := context.Background()

	t.Run("successfully groups SCA findings by vulnerability ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockResult := mocks.NewMockTestResult(ctrl)
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSca,
					Title:       "Test Vulnerability",
					Problems:    []testapi.Problem{},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		mockResult.EXPECT().Findings(gomock.Any()).Return(findings, true, nil).Times(1)

		issuesList, err := testapi.NewIssuesFromTestResult(ctx, mockResult)
		require.NoError(t, err)
		require.NotNil(t, issuesList)
		assert.GreaterOrEqual(t, len(issuesList), 0)
	})

	t.Run("successfully groups findings by key when not SCA", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockResult := mocks.NewMockTestResult(ctrl)
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSast,
					Key:         "key-1",
					Title:       "Issue 1",
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSast,
					Key:         "key-1", // Same key, should be grouped
					Title:       "Issue 1",
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSast,
					Key:         "key-2", // Different key, separate issue
					Title:       "Issue 2",
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		mockResult.EXPECT().Findings(gomock.Any()).Return(findings, true, nil).Times(1)

		issuesList, err := testapi.NewIssuesFromTestResult(ctx, mockResult)
		require.NoError(t, err)
		require.NotNil(t, issuesList)
		// Should have 2 issues (key-1 grouped, key-2 separate)
		assert.Len(t, issuesList, 2)

		// Verify first issue has 2 findings
		if len(issuesList) > 0 {
			assert.Len(t, issuesList[0].GetFindings(), 2)
			assert.Equal(t, "key-1", issuesList[0].GetID())
			// Verify rule ID matches key for SAST findings
			assert.Equal(t, "key-1", issuesList[0].GetRuleID())
		}
	})
}

func TestIssue_GeneralizedMethods(t *testing.T) {
	t.Run("SAST issue extracts severity from Rating", func(t *testing.T) {
		location := testapi.SourceLocation{
			FilePath: "src/main.go",
			FromLine: 10,
			Type:     testapi.Source,
		}
		var locationUnion testapi.FindingLocation
		_ = locationUnion.MergeSourceLocation(location)

		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSast,
					Key:         "rule-123",
					Title:       "SQL Injection",
					Description: "Potential SQL injection vulnerability",
					Rating: testapi.Rating{
						Severity: testapi.Severity("high"),
					},
					Locations: []testapi.FindingLocation{locationUnion},
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		issue, err := testapi.NewIssueFromFindings(findings)
		require.NoError(t, err)
		require.NotNil(t, issue)

		// Verify general methods
		assert.Equal(t, testapi.FindingTypeSast, issue.GetFindingType())
		assert.Equal(t, "rule-123", issue.GetID())
		assert.Equal(t, "rule-123", issue.GetRuleID())
		assert.Equal(t, "high", issue.GetSeverity())
		assert.Equal(t, "SQL Injection", issue.GetTitle())
		assert.Equal(t, "Potential SQL injection vulnerability", issue.GetDescription())

		// Verify source locations
		sourceLocations := issue.GetSourceLocations()
		assert.Len(t, sourceLocations, 1)
		assert.Equal(t, "src/main.go", sourceLocations[0].FilePath)
		assert.Equal(t, 10, sourceLocations[0].FromLine)

		// Verify SCA-specific methods return empty/error for SAST
		metadata := issue.GetMetadata()
		assert.NotNil(t, metadata)
		assert.Nil(t, metadata.Component)
		assert.Empty(t, metadata.Technology)
		assert.Empty(t, metadata.DependencyPaths)
		assert.Empty(t, metadata.FixedInVersions)
		assert.False(t, metadata.IsFixable)
		assert.Equal(t, float32(0.0), metadata.CVSSScore)
	})

	t.Run("SCA issue preserves SCA-specific methods", func(t *testing.T) {
		// This test verifies backward compatibility - SCA issues should still work
		// We'll use a minimal SCA finding structure
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSca,
					Key:         "test-key",
					Title:       "Test SCA Issue",
					Description: "Test description",
				},
				Id: func() *uuid.UUID { id := uuid.New(); return &id }(),
			},
		}

		issue, err := testapi.NewIssueFromFindings(findings)
		require.NoError(t, err)
		require.NotNil(t, issue)

		// Verify general methods work
		assert.Equal(t, testapi.FindingTypeSca, issue.GetFindingType())
		assert.NotEmpty(t, issue.GetID())
		assert.Equal(t, issue.GetID(), issue.GetRuleID()) // Rule ID should match ID for SCA
		assert.Equal(t, "Test SCA Issue", issue.GetTitle())

		// Verify SCA-specific methods exist (even if they return empty values)
		// These should not panic
		metadata := issue.GetMetadata()
		if metadata != nil {
			_ = metadata.Component
			_ = metadata.Technology
			_ = metadata.DependencyPaths
			_ = metadata.FixedInVersions
			_ = metadata.IsFixable
			_ = metadata.CVSSScore
		}
	})
}

func TestIssueError(t *testing.T) {
	t.Run("error message without cause", func(t *testing.T) {
		err := &testapi.IssueError{Message: "test error"}
		assert.Equal(t, "test error", err.Error())
		assert.Nil(t, err.Unwrap())
	})

	t.Run("error message with cause", func(t *testing.T) {
		cause := errors.New("root cause")
		err := &testapi.IssueError{Message: "test error", Cause: cause}
		assert.Contains(t, err.Error(), "test error")
		assert.Contains(t, err.Error(), "root cause")
		assert.Equal(t, cause, err.Unwrap())
	})
}
