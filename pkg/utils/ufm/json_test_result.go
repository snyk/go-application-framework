package ufm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// jsonTestResult is an unexported, JSON-serializable implementation of testapi.TestResult.
// Use NewSerializableTestResult to create instances of this type.
type jsonTestResult struct {
	TestID            *uuid.UUID                      `json:"testId,omitempty"`
	TestConfiguration *testapi.TestConfiguration      `json:"testConfiguration,omitempty"`
	CreatedAt         *time.Time                      `json:"createdAt,omitempty"`
	TestSubject       testapi.TestSubject             `json:"testSubject"`
	SubjectLocators   *[]testapi.TestSubjectLocator   `json:"subjectLocators,omitempty"`
	ExecutionState    testapi.TestExecutionStates     `json:"executionState"`
	Errors            *[]testapi.IoSnykApiCommonError `json:"errors,omitempty"`
	Warnings          *[]testapi.IoSnykApiCommonError `json:"warnings,omitempty"`
	PassFail          *testapi.PassFail               `json:"passFail,omitempty"`
	OutcomeReason     *testapi.TestOutcomeReason      `json:"outcomeReason,omitempty"`
	BreachedPolicies  *testapi.PolicyRefSet           `json:"breachedPolicies,omitempty"`
	EffectiveSummary  *testapi.FindingSummary         `json:"effectiveSummary,omitempty"`
	RawSummary        *testapi.FindingSummary         `json:"rawSummary,omitempty"`
	FindingsData      []testapi.FindingData           `json:"findings,omitempty"`
	FindingsComplete  bool                            `json:"findingsComplete"`
}

// GetTestID returns the test ID.
func (j *jsonTestResult) GetTestID() *uuid.UUID {
	return j.TestID
}

// GetTestConfiguration returns the test configuration.
func (j *jsonTestResult) GetTestConfiguration() *testapi.TestConfiguration {
	return j.TestConfiguration
}

// GetCreatedAt returns the creation timestamp.
func (j *jsonTestResult) GetCreatedAt() *time.Time {
	return j.CreatedAt
}

// GetTestSubject returns the test subject.
func (j *jsonTestResult) GetTestSubject() testapi.TestSubject {
	return j.TestSubject
}

// GetSubjectLocators returns the subject locators.
func (j *jsonTestResult) GetSubjectLocators() *[]testapi.TestSubjectLocator {
	return j.SubjectLocators
}

// GetExecutionState returns the execution state.
func (j *jsonTestResult) GetExecutionState() testapi.TestExecutionStates {
	return j.ExecutionState
}

// GetErrors returns any errors encountered during test execution.
func (j *jsonTestResult) GetErrors() *[]testapi.IoSnykApiCommonError {
	return j.Errors
}

// GetWarnings returns any warnings encountered during test execution.
func (j *jsonTestResult) GetWarnings() *[]testapi.IoSnykApiCommonError {
	return j.Warnings
}

// GetPassFail returns the pass/fail outcome.
func (j *jsonTestResult) GetPassFail() *testapi.PassFail {
	return j.PassFail
}

// GetOutcomeReason returns the outcome reason.
func (j *jsonTestResult) GetOutcomeReason() *testapi.TestOutcomeReason {
	return j.OutcomeReason
}

// GetBreachedPolicies returns breached policies.
func (j *jsonTestResult) GetBreachedPolicies() *testapi.PolicyRefSet {
	return j.BreachedPolicies
}

// GetEffectiveSummary returns the effective summary (excluding suppressed findings).
func (j *jsonTestResult) GetEffectiveSummary() *testapi.FindingSummary {
	return j.EffectiveSummary
}

// GetRawSummary returns the raw summary (including suppressed findings).
func (j *jsonTestResult) GetRawSummary() *testapi.FindingSummary {
	return j.RawSummary
}

// Findings returns the stored findings without making any API calls.
// The complete parameter indicates whether all findings were successfully fetched.
func (j *jsonTestResult) Findings(ctx context.Context) (resultFindings []testapi.FindingData, complete bool, err error) {
	return j.FindingsData, j.FindingsComplete, nil
}

// NewSerializableTestResult converts a testapi.TestResult to a JSON-serializable format.
// It fetches findings from the source TestResult and stores them in the returned struct.
// The returned TestResult can be safely marshaled to JSON using json.Marshal.
func NewSerializableTestResult(ctx context.Context, tr testapi.TestResult) (testapi.TestResult, error) {
	if tr == nil {
		return nil, fmt.Errorf("testResult cannot be nil")
	}

	// Fetch findings from the source
	findings, complete, err := tr.Findings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch findings: %w", err)
	}

	// Create the JSON-serializable result
	result := &jsonTestResult{
		TestID:            tr.GetTestID(),
		TestConfiguration: tr.GetTestConfiguration(),
		CreatedAt:         tr.GetCreatedAt(),
		TestSubject:       tr.GetTestSubject(),
		SubjectLocators:   tr.GetSubjectLocators(),
		ExecutionState:    tr.GetExecutionState(),
		Errors:            tr.GetErrors(),
		Warnings:          tr.GetWarnings(),
		PassFail:          tr.GetPassFail(),
		OutcomeReason:     tr.GetOutcomeReason(),
		BreachedPolicies:  tr.GetBreachedPolicies(),
		EffectiveSummary:  tr.GetEffectiveSummary(),
		RawSummary:        tr.GetRawSummary(),
		FindingsData:      findings,
		FindingsComplete:  complete,
	}

	return result, nil
}

func NewSerializableTestResultFromBytes(jsonBytes []byte) ([]testapi.TestResult, error) {
	var tmp []jsonTestResult
	err := json.Unmarshal(jsonBytes, &tmp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal test result: %w", err)
	}

	testResults := make([]testapi.TestResult, len(tmp))
	for i, r := range tmp {
		testResults[i] = &r
	}

	return testResults, nil
}
