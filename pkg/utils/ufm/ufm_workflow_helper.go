package ufm

import (
	"context"
	"encoding/json"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// CreateWorkflowDataFromTest converts a test and its results to JSON-serializable format,
// serializes them to JSON bytes, and wraps them in workflow.Data.
// This ensures the data can be safely persisted, cached, or transmitted.
//
// Metadata describes the test as a whole, such as the asset it covers.
func CreateWorkflowDataFromTest(id workflow.Identifier, metadata map[string]interface{}, results []testapi.TestResult) workflow.Data {
	if len(results) == 0 {
		return nil
	}

	// Convert to serializable format to ensure data is truly JSON-serializable
	ctx := context.Background()
	serializableResults := make([]*jsonTestResult, 0, len(results))
	for _, result := range results {
		serializable, err := newSerializableTestResult(ctx, result)
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
	jsonBytes, err := json.Marshal(jsonTest{Metadata: metadata, Results: serializableResults})
	if err != nil {
		return nil
	}

	data := workflow.NewData(workflow.NewTypeIdentifier(id, "TestResult"), content_type.UFM_RESULT, jsonBytes)
	return data
}

// CreateWorkflowDataFromTestResults wraps results as a test carrying no metadata of its own.
//
// Use CreateWorkflowDataFromTest where there are facts describing the test as a whole, such
// as the asset it covers, rather than any one result.
func CreateWorkflowDataFromTestResults(id workflow.Identifier, results []testapi.TestResult) workflow.Data {
	return CreateWorkflowDataFromTest(id, nil, results)
}

// GetTestFromWorkflowData extracts and deserializes a test and its results from
// workflow.Data. The data is expected to be JSON bytes created by
// CreateWorkflowDataFromTest. It returns nil if data holds no test.
func GetTestFromWorkflowData(data workflow.Data) *Test {
	if data.GetContentType() != content_type.UFM_RESULT {
		return nil
	}

	// Deserialize from JSON bytes
	jsonBytes, ok := data.GetPayload().([]byte)
	if !ok {
		return nil
	}

	test, err := NewSerializableTestFromBytes(jsonBytes)
	if err != nil {
		return nil
	}
	return test
}

// GetTestResultsFromWorkflowData extracts and deserializes the results of a test from
// workflow.Data, discarding the metadata of the test itself.
func GetTestResultsFromWorkflowData(data workflow.Data) []testapi.TestResult {
	test := GetTestFromWorkflowData(data)
	if test == nil {
		return nil
	}
	return test.Results
}
