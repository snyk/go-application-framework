package ufm

import (
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func CreateData(id workflow.Identifier, results []testapi.TestResult) workflow.Data {
	if len(results) == 0 {
		return nil
	}

	// TODO: look into serializing the results to json and then back to TestResult
	data := workflow.NewData(workflow.NewTypeIdentifier(id, "TestResult"), content_type.UFM_RESULT, results)
	return data
}

func GetTestResults(data workflow.Data) []testapi.TestResult {
	if data.GetContentType() != content_type.UFM_RESULT {
		return nil
	}

	result, ok := data.GetPayload().([]testapi.TestResult)
	if !ok {
		return nil
	}
	return result
}
