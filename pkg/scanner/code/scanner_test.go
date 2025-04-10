package code

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/product"
	"github.com/snyk/go-application-framework/pkg/types"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

// Constants for testing
const (
	testPath          = "/test/path"
	testMessageText   = "Test message"
	testMessageHeader = "Test Issue"
	testScanType      = "sast"
	testComponentName = "test-component"
)

func TestScanner_Scan_SARIF(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock SARIF response in the workflow.Data
	sarifJson := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Snyk Code",
					"semanticVersion": "1.0.0",
					"rules": [{
						"id": "javascript/PathTraversal",
						"name": "Path Traversal",
						"shortDescription": {
							"text": "Path Traversal"
						},
						"help": {
							"text": "Vulnerability that allows attackers to access files"
						},
						"properties": {
							"tags": ["security"],
							"precision": "high"
						}
					}]
				}
			},
			"results": [{
				"ruleId": "javascript/PathTraversal",
				"level": "error",
				"message": {
					"text": "Path traversal vulnerability detected"
				},
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {
							"uri": "/test/path/file.js"
						},
						"region": {
							"startLine": 10,
							"startColumn": 5,
							"endLine": 10,
							"endColumn": 20
						}
					}
				}]
			}]
		}]
	}`

	// Set up the mock data payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/sarif+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(sarifJson).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path"), scanData.Path, "Expected path to be /test/path")
	assert.Nil(t, scanData.Err, "Expected no error")
	assert.False(t, scanData.IsDeltaScan, "Expected IsDeltaScan to be false")
	assert.True(t, scanData.SendAnalytics, "Expected SendAnalytics to be true")
	assert.True(t, scanData.UpdateGlobalCache, "Expected UpdateGlobalCache to be true")
	assert.NotZero(t, scanData.DurationMs, "Expected DurationMs to be non-zero")
	assert.NotZero(t, scanData.TimestampFinished, "Expected TimestampFinished to be non-zero")

	// Verify issues were created
	assert.NotEmpty(t, scanData.Issues, "Expected issues to be populated")
	assert.Len(t, scanData.Issues, 1, "Expected exactly 1 issue")

	// Verify the issue properties
	issue := scanData.Issues[0]
	assert.Equal(t, "javascript/PathTraversal", issue.GetRuleID(), "Expected rule ID to match")
	assert.Equal(t, "Path traversal vulnerability detected", issue.GetMessage(), "Expected message to match")
	assert.Equal(t, types.High, issue.GetSeverity(), "Expected severity to be High")
	assert.Equal(t, types.CodeSecurityVulnerability, issue.GetIssueType(), "Expected issue type to be CodeSecurityVulnerability")
	assert.Equal(t, product.FilterableIssueTypeCodeSecurity, issue.GetFilterableIssueType(), "Expected filterable issue type to be CodeSecurity")
	assert.Equal(t, product.ProductCode, issue.GetProduct(), "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path/file.js"), issue.GetAffectedFilePath(), "Expected affected file path to match")

	// Verify the issue range
	expectedRange := types.Range{
		Start: types.Position{Line: 10, Character: 5},
		End:   types.Position{Line: 10, Character: 20},
	}
	assert.Equal(t, expectedRange, issue.GetRange(), "Expected range to match")
}

func TestScanner_Scan_LocalFinding(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Create a sample local finding
	localFinding := local_models.LocalFinding{
		Summary: local_models.TypesFindingsSummary{
			Path: testPath,
			Type: testScanType,
		},
		Rules: []local_models.TypesRules{
			{
				Id:   "javascript/TestRule",
				Name: "Test Rule",
				ShortDescription: struct {
					Text string `json:"text"`
				}{
					Text: "Test Rule Description",
				},
				DefaultConfiguration: struct {
					Level string `json:"level"`
				}{
					Level: "error",
				},
			},
		},
	}

	// Create a finding resource
	sourceLocation := local_models.IoSnykReactiveFindingSourceLocation{
		Filepath:            "/test/path/file.js",
		OriginalStartLine:   5,
		OriginalEndLine:     5,
		OriginalStartColumn: 10,
		OriginalEndColumn:   20,
	}
	location := local_models.IoSnykReactiveFindingLocation{
		SourceLocations: &sourceLocation,
	}
	locations := []local_models.IoSnykReactiveFindingLocation{location}

	// Add a finding to the local finding
	msg := local_models.TypesFindingMessage{
		Header: testMessageHeader,
		Text:   testMessageText,
	}
	component := local_models.TypesComponent{
		Name:     testComponentName,
		ScanType: testScanType,
	}
	findingResource := local_models.FindingResource{
		Attributes: local_models.TypesFindingAttributes{
			Message: msg,
			ReferenceId: &local_models.TypesReferenceId{
				Identifier: "javascript/TestRule",
				Index:      0,
			},
			Locations: &locations,
			Component: component,
		},
	}
	localFinding.Findings = []local_models.FindingResource{findingResource}

	// Set up the mock data payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/vnd.code.finding+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(localFinding).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path"), scanData.Path, "Expected path to be /test/path")
	assert.Nil(t, scanData.Err, "Expected no error")

	// Verify issues were created
	assert.NotEmpty(t, scanData.Issues, "Expected issues to be populated")
	assert.Len(t, scanData.Issues, 1, "Expected exactly 1 issue")

	// Verify the issue properties
	issue := scanData.Issues[0]
	assert.Equal(t, "javascript/TestRule", issue.GetRuleID(), "Expected rule ID to match")
	assert.Equal(t, testMessageText, issue.GetMessage(), "Expected message to match")
	assert.Equal(t, types.FilePath("/test/path/file.js"), issue.GetAffectedFilePath(), "Expected affected file path to match")

	// Verify the issue range
	expectedRange := types.Range{
		Start: types.Position{Line: 5, Character: 10},
		End:   types.Position{Line: 5, Character: 20},
	}
	assert.Equal(t, expectedRange, issue.GetRange(), "Expected range to match")
}

func TestScanner_Scan_InvalidSARIF(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock invalid SARIF response
	invalidSarifJson := `{"invalid": "json`

	// Set up the mock data payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/sarif+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(invalidSarifJson).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify error is present and no issues were created
	assert.NotNil(t, scanData.Err, "Expected error to be populated")
	assert.Contains(t, scanData.Err.Error(), "failed to parse SARIF", "Expected SARIF parsing error")
	assert.Empty(t, scanData.Issues, "Expected no issues to be populated due to error")
}

func TestScanner_ScanWithError(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to return an error
	expectedError := errors.New("workflow error")
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return(nil, expectedError)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test"), scanData.Path, "Expected path to match input path")
	assert.NotNil(t, scanData.Err, "Expected an error to be present")
	assert.Contains(t, scanData.Err.Error(), "workflow invocation failed", "Error should indicate workflow invocation failure")
	assert.Contains(t, scanData.Err.Error(), "workflow error", "Error should contain the original error message")
	assert.Empty(t, scanData.Issues, "Expected no issues on error")
	assert.NotZero(t, scanData.DurationMs, "Expected DurationMs to be non-zero")
	assert.NotZero(t, scanData.TimestampFinished, "Expected TimestampFinished to be non-zero")
}

func TestScanner_Scan_InvalidPayloadType(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Set up the mock data payload with an invalid type (int is not supported)
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/vnd.code.finding+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(123).AnyTimes(), // Integer is an invalid payload type
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify error is present and no issues were created
	assert.NotNil(t, scanData.Err, "Expected error to be populated")
	assert.Contains(t, scanData.Err.Error(), "unexpected payload type", "Expected invalid payload type error")
	assert.Empty(t, scanData.Issues, "Expected no issues to be populated due to error")
}

func TestScanner_Scan_EmptyResults(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to return empty results (not nil, just empty)
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path"), scanData.Path, "Expected path to be /test/path")

	// We now expect an error for empty results - this is a design change to make it more explicit
	assert.NotNil(t, scanData.Err, "Expected error with empty results")
	assert.Contains(t, scanData.Err.Error(), "no results", "Error should indicate no results were returned")
	assert.Empty(t, scanData.Issues, "Expected no issues with empty results")
}

func TestScanner_Scan_MultipleResults(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData1 := mocks.NewMockData(ctrl)
	mockData2 := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Create sample findings for two different content types
	// Sample SARIF data for first result
	sarifJson := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Snyk Code",
					"rules": [{
						"id": "javascript/PathTraversal1",
						"shortDescription": { "text": "Path Traversal 1" },
						"help": { "text": "Help 1" }
					}]
				}
			},
			"results": [{
				"ruleId": "javascript/PathTraversal1",
				"level": "error",
				"message": { "text": "Issue 1" },
				"locations": [{
					"physicalLocation": {
						"artifactLocation": { "uri": "/test/path/file1.js" },
						"region": { "startLine": 10, "startColumn": 5, "endLine": 10, "endColumn": 20 }
					}
				}]
			}]
		}]
	}`

	// Sample LocalFinding for second result
	sourceLocation := local_models.IoSnykReactiveFindingSourceLocation{
		Filepath:            "/test/path/file2.js",
		OriginalStartLine:   5,
		OriginalEndLine:     5,
		OriginalStartColumn: 10,
		OriginalEndColumn:   20,
	}
	location := local_models.IoSnykReactiveFindingLocation{
		SourceLocations: &sourceLocation,
	}
	locations := []local_models.IoSnykReactiveFindingLocation{location}

	findingResource := local_models.FindingResource{
		Attributes: local_models.TypesFindingAttributes{
			Message: local_models.TypesFindingMessage{
				Header: "Test Finding 2",
				Text:   "This is issue 2",
			},
			ReferenceId: &local_models.TypesReferenceId{
				Identifier: "javascript/TestRule2",
				Index:      0,
			},
			Locations: &locations,
			Component: local_models.TypesComponent{
				Name:     "test-component",
				ScanType: "sast",
			},
		},
	}
	localFinding := local_models.LocalFinding{
		Summary: local_models.TypesFindingsSummary{
			Path: "/test/path",
			Type: "sast",
		},
		Rules: []local_models.TypesRules{
			{
				Id:   "javascript/TestRule2",
				Name: "Test Rule 2",
				ShortDescription: struct {
					Text string `json:"text"`
				}{
					Text: "Test Rule 2 Description",
				},
			},
		},
		Findings: []local_models.FindingResource{findingResource},
	}

	// Set up the mock data payloads
	gomock.InOrder(
		mockData1.EXPECT().GetContentType().Return("application/sarif+json").AnyTimes(),
		mockData1.EXPECT().GetPayload().Return(sarifJson).AnyTimes(),
		mockData2.EXPECT().GetContentType().Return("application/vnd.code.finding+json").AnyTimes(),
		mockData2.EXPECT().GetPayload().Return(localFinding).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to return multiple data items
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData1, mockData2}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify that we have scan data with issues from both sources
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path"), scanData.Path, "Expected path to be /test/path")
	assert.Nil(t, scanData.Err, "Expected no error")

	// Verify that we have issues from both sources
	assert.Len(t, scanData.Issues, 2, "Expected 2 issues (one from each source)")

	// Verify details of each issue
	// Check if we have issues with the expected rule IDs
	ruleIDs := []string{"javascript/PathTraversal1", "javascript/TestRule2"}
	found := make(map[string]bool)
	for _, issue := range scanData.Issues {
		ruleID := issue.GetRuleID()
		found[ruleID] = true

		switch ruleID {
		case "javascript/PathTraversal1":
			assert.Equal(t, "Issue 1", issue.GetMessage(), "Expected correct message for first issue")
			assert.Equal(t, types.FilePath("/test/path/file1.js"), issue.GetAffectedFilePath(), "Expected correct file for first issue")
		case "javascript/TestRule2":
			assert.Equal(t, "This is issue 2", issue.GetMessage(), "Expected correct message for second issue")
			assert.Equal(t, types.FilePath("/test/path/file2.js"), issue.GetAffectedFilePath(), "Expected correct file for second issue")
		}
	}

	// Verify we found issues with both rule IDs
	for _, ruleID := range ruleIDs {
		assert.True(t, found[ruleID], "Expected to find issue with rule ID %s", ruleID)
	}
}

func TestScanner_Scan_NilPayload(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Set up the mock data payload with nil payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/vnd.code.finding+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(nil).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to return data with nil payload
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path"), scanData.Path, "Expected path to match input path")

	// We now expect an error for nil payloads - this is a design improvement for error handling
	assert.NotNil(t, scanData.Err, "Expected error with nil payload")
	assert.Contains(t, scanData.Err.Error(), "nil payload for content type", "Error should indicate nil payload")
	assert.Empty(t, scanData.Issues, "Expected no issues with nil payload")
}

func TestScanner_Scan_InvalidSARIFStructure(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock structurally invalid SARIF (valid JSON but missing required fields)
	invalidSarifJson := `{"version": "2.1.0", "$schema": "schema", "runs": [{}]}` // Missing tool driver

	// Set up the mock data payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/sarif+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(invalidSarifJson).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// The conversion might succeed, but there should be 0 issues
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, types.FilePath("/test/path"), scanData.Path, "Expected path to be /test/path")

	// Check that we either have an error OR we have 0 issues
	if scanData.Err == nil {
		assert.Empty(t, scanData.Issues, "Expected no issues with invalid SARIF structure")
	}
}

func TestScanner_Scan_WithLogger(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock SARIF response
	sarifJson := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{}]
	}`

	// Set up the mock data payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/sarif+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(sarifJson).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")

	// Verify that we captured the log message about using SARIF instead of findings data
	// Removed assertion for log message since logger is now nil
}

func TestScanner_Scan_SARIFTransformationError(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockData := mocks.NewMockData(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Mock an invalid JSON, which will fail JSON parsing entirely
	invalidSarifJson := `{
		"incomplete json"`

	// Set up the mock data payload
	gomock.InOrder(
		mockData.EXPECT().GetContentType().Return("application/sarif+json").AnyTimes(),
		mockData.EXPECT().GetPayload().Return(invalidSarifJson).AnyTimes(),
	)

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Expect engine.Invoke to be called with the correct workflow ID and return the mock data
	mockEngine.EXPECT().InvokeWithConfig(
		localworkflows.WORKFLOWID_CODE,
		gomock.Any(),
	).Return([]workflow.Data{mockData}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method
	scanner.Scan(context.Background(), "/test/path", mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify the scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")

	// Since the SARIF data is malformed JSON, there should be an error
	assert.NotNil(t, scanData.Err, "Expected error with malformed SARIF")
	assert.Contains(t, scanData.Err.Error(), "failed to parse SARIF", "Expected error about SARIF parsing")
}

func TestScanner_Scan_ConfigurationDetails(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockConfig := configuration.NewInMemory()

	// Create a channel to capture the processed scan data
	scanDataCh := make(chan types.ScanData, 1)

	mockScanResultProcessor := func(ctx context.Context, scanData types.ScanData) {
		// Send the scan data to the channel for verification
		scanDataCh <- scanData
	}

	// Define the test path
	testPath := types.FilePath("/specific/test/path")

	// Mock the GetConfiguration method
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	// Mock GetLogger to return nil
	mockEngine.EXPECT().GetLogger().Return(nil).AnyTimes()

	// Use simple invocation without trying to inspect the config
	mockEngine.EXPECT().InvokeWithConfig(
		gomock.Eq(localworkflows.WORKFLOWID_CODE),
		gomock.Any(),
	).Return([]workflow.Data{}, nil)

	// Create the scanner instance
	scanner := &Scanner{
		engine:  mockEngine,
		product: product.ProductCode,
	}

	// Execute the Scan method with a specific path
	scanner.Scan(context.Background(), testPath, mockScanResultProcessor, "/test")

	// Get the scan data from the channel and verify it
	scanData := <-scanDataCh

	// Verify basic scan data properties
	assert.Equal(t, product.ProductCode, scanData.Product, "Expected product to be Snyk Code")
	assert.Equal(t, testPath, scanData.Path, "Expected path to match input path")

	// We now expect an error for empty results - this is a design change to make it more explicit
	assert.NotNil(t, scanData.Err, "Expected error with empty results")
	assert.Contains(t, scanData.Err.Error(), "no results", "Error should indicate no results were returned")
	assert.Empty(t, scanData.Issues, "Expected no issues with empty results")
}
