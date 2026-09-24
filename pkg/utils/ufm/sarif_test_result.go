package ufm

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/code-client-go/sarif"

	"github.com/snyk/go-application-framework/internal/ufm_helpers"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
)

type sarifTestResult struct {
	findings         []testapi.FindingData
	effectiveSummary *testapi.FindingSummary
	rawSummary       *testapi.FindingSummary
	metadata         map[string]interface{}
	testSubject      *testapi.TestSubject
}

func newSarifTestResult(
	findings []testapi.FindingData,
	effectiveSummary *testapi.FindingSummary,
	rawSummary *testapi.FindingSummary,
	testSummary *json_schemas.TestSummary,
	sarifDoc *sarif.SarifDocument,
) testapi.TestResult {
	result := &sarifTestResult{
		findings:         findings,
		effectiveSummary: effectiveSummary,
		rawSummary:       rawSummary,
		metadata:         make(map[string]interface{}),
	}

	if testSummary != nil {
		result.metadata["path"] = testSummary.Path
		result.metadata["type"] = testSummary.Type
		result.metadata["artifacts"] = testSummary.Artifacts
	}

	if sarifDoc != nil && len(sarifDoc.Runs) > 0 {
		if coverage := sarifDoc.Runs[0].Properties.Coverage; len(coverage) > 0 {
			entries := make([]ufm_helpers.Coverage, 0, len(coverage))
			for _, c := range coverage {
				entries = append(entries, ufm_helpers.Coverage(c))
			}
			result.metadata[ufm_helpers.MetadataKeyCoverage] = entries
		}
	}

	return result
}

func (s *sarifTestResult) GetTestID() *uuid.UUID { return nil }

// GetTestConfiguration declares a SAST scan so consumers can identify the
// product even when there are no findings to infer it from.
func (s *sarifTestResult) GetTestConfiguration() *testapi.TestConfiguration {
	return &testapi.TestConfiguration{ScanConfig: &testapi.ScanConfiguration{Sast: &testapi.SastScanConfiguration{}}}
}
func (s *sarifTestResult) GetCreatedAt() *time.Time             { return nil }
func (s *sarifTestResult) GetTestSubject() *testapi.TestSubject { return s.testSubject }
func (s *sarifTestResult) GetSubjectLocators() *[]testapi.TestSubjectLocator {
	return nil
}
func (s *sarifTestResult) GetTestResources() *[]testapi.TestResource { return nil }
func (s *sarifTestResult) GetExecutionState() testapi.TestExecutionStates {
	return testapi.TestExecutionStatesFinished
}
func (s *sarifTestResult) GetErrors() *[]testapi.IoSnykApiCommonError   { return nil }
func (s *sarifTestResult) GetWarnings() *[]testapi.IoSnykApiCommonError { return nil }
func (s *sarifTestResult) GetPassFail() *testapi.PassFail               { return nil }
func (s *sarifTestResult) GetOutcomeReason() *testapi.TestOutcomeReason { return nil }
func (s *sarifTestResult) GetBreachedPolicies() *testapi.PolicyRefSet   { return nil }

func (s *sarifTestResult) GetEffectiveSummary() *testapi.FindingSummary {
	return s.effectiveSummary
}

func (s *sarifTestResult) GetRawSummary() *testapi.FindingSummary {
	return s.rawSummary
}

func (s *sarifTestResult) GetTestFacts() *[]testapi.TestFact { return nil }

func (s *sarifTestResult) SetMetadata(key string, value interface{}) {
	s.metadata[key] = value
}

func (s *sarifTestResult) GetMetadataValue(key string) interface{} {
	return s.metadata[key]
}

func (s *sarifTestResult) GetMetadata() map[string]interface{} {
	return s.metadata
}

func (s *sarifTestResult) Findings(_ context.Context) ([]testapi.FindingData, bool, error) {
	return s.findings, true, nil
}

func (s *sarifTestResult) Get(key testapi.TestResultKeys) interface{} {
	switch key {
	case testapi.TestResultTestSubject:
		return s.testSubject
	case testapi.TestResultRawSummary:
		return s.rawSummary
	case testapi.TestResultMetadata:
		return s.metadata
	default:
		return nil
	}
}
