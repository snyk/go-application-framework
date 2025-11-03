package ufm

import (
	"context"
	"encoding/json"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// CreateWorkflowDataFromTestResults converts TestResults to JSON-serializable format,
// serializes them to JSON bytes, and wraps them in workflow.Data.
// This ensures the results can be safely persisted, cached, or transmitted.
func CreateWorkflowDataFromTestResults(id workflow.Identifier, results []testapi.TestResult) workflow.Data {
	if len(results) == 0 {
		return nil
	}

	// Convert to serializable format to ensure data is truly JSON-serializable
	ctx := context.Background()
	serializableResults := make([]testapi.TestResult, 0, len(results))
	for _, result := range results {
		serializable, err := NewSerializableTestResult(ctx, result)
		if err != nil {
			// If serialization fails, skip this result
			// This could happen if findings fetch fails
			continue
		}
		serializableResults = append(serializableResults, serializable)
	}

	if len(serializableResults) == 0 {
		return nil
	}

	// Serialize to JSON bytes
	jsonBytes, err := json.Marshal(serializableResults)
	if err != nil {
		return nil
	}

	data := workflow.NewData(workflow.NewTypeIdentifier(id, "TestResult"), content_type.UFM_RESULT, jsonBytes)
	return data
}

// GetTestResultsFromWorkflowData extracts and deserializes TestResults from workflow.Data.
// The data is expected to be JSON bytes created by CreateWorkflowDataFromTestResults.
func GetTestResultsFromWorkflowData(data workflow.Data) []testapi.TestResult {
	if data.GetContentType() != content_type.UFM_RESULT {
		return nil
	}

	payload := data.GetPayload()

	// Deserialize from JSON bytes
	jsonBytes, ok := payload.([]byte)
	if !ok {
		return nil
	}

	var results []*jsonTestResult
	if err := json.Unmarshal(jsonBytes, &results); err != nil {
		return nil
	}

	// Convert to []testapi.TestResult
	testResults := make([]testapi.TestResult, len(results))
	for i, r := range results {
		testResults[i] = r
	}
	return testResults
}
