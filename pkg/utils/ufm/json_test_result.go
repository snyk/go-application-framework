package ufm

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
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
	TestSubject       *testapi.TestSubject            `json:"testSubject,omitempty"`
	SubjectLocators   *[]testapi.TestSubjectLocator   `json:"subjectLocators,omitempty"`
	TestResources	  *[]testapi.TestResource 		  `json:"testResources,omitempty"`
	ExecutionState    testapi.TestExecutionStates     `json:"executionState"`
	Errors            *[]testapi.IoSnykApiCommonError `json:"errors,omitempty"`
	Warnings          *[]testapi.IoSnykApiCommonError `json:"warnings,omitempty"`
	PassFail          *testapi.PassFail               `json:"passFail,omitempty"`
	OutcomeReason     *testapi.TestOutcomeReason      `json:"outcomeReason,omitempty"`
	BreachedPolicies  *testapi.PolicyRefSet           `json:"breachedPolicies,omitempty"`
	EffectiveSummary  *testapi.FindingSummary         `json:"effectiveSummary,omitempty"`
	RawSummary        *testapi.FindingSummary         `json:"rawSummary,omitempty"`
	FindingsComplete  bool                            `json:"findingsComplete"`
	Metadata          map[string]interface{}          `json:"metadata,omitempty"`
	// Optimized wire format: central problem store (optional, for serialization)
	ProblemStore map[string]json.RawMessage `json:"problemStore,omitempty"`
	ProblemRefs  map[string][]string        `json:"_problemRefs,omitempty"`

	// Findings (problems removed when using problemStore)
	FindingsData []testapi.FindingData `json:"findings,omitempty"`

	// In-memory cache of full findings (not serialized, used after deserialization)
	fullFindings []testapi.FindingData `json:"-"`

	mutex sync.Mutex
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
func (j *jsonTestResult) GetTestSubject() *testapi.TestSubject {
	return j.TestSubject
}

// GetSubjectLocators returns the subject locators.
func (j *jsonTestResult) GetSubjectLocators() *[]testapi.TestSubjectLocator {
	return j.SubjectLocators
}

// GetResources returns the test resources.
func (j *jsonTestResult) GetTestResources() *[]testapi.TestResource {
	return j.TestResources
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

// SetMetadata sets the metadata for the given key.
func (j *jsonTestResult) SetMetadata(key string, value interface{}) {
	j.Metadata[key] = value
}

// GetMetadata returns the metadata for the given key.
func (j *jsonTestResult) GetMetadata() map[string]interface{} {
	return j.Metadata
}

// Findings returns the stored findings without making any API calls.
// The complete parameter indicates whether all findings were successfully fetched.
func (j *jsonTestResult) Findings(ctx context.Context) (resultFindings []testapi.FindingData, complete bool, err error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	// Return fullFindings if available (reconstructed from optimized format)
	if j.fullFindings != nil {
		return j.fullFindings, j.FindingsComplete, nil
	}

	// Optimized format: lazy reconstruction on first access
	if len(j.ProblemStore) > 0 && len(j.ProblemRefs) > 0 {
		if err := ReconstructFindings(j); err != nil {
			return nil, false, fmt.Errorf("failed to reconstruct findings: %w", err)
		}
		return j.fullFindings, j.FindingsComplete, nil
	}

	// Old format: return as-is (mainly used in tests, no optimization needed)
	return j.FindingsData, j.FindingsComplete, nil
}

// NewSerializableTestResult converts a testapi.TestResult to a JSON-serializable format.
// It fetches findings from the source TestResult and optimizes the format by:
// 1. Extracting problems into a central problemStore
// 2. Replacing problems in findings with references
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

	// Build optimized format
	problemStore, problemRefs, optimizedFindings := BuildOptimizedFormat(findings)

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
		FindingsComplete:  complete,
		ProblemStore:      problemStore,
		ProblemRefs:       problemRefs,
		FindingsData:      optimizedFindings,
		fullFindings:      findings, // Keep original for Findings() method
		Metadata:          tr.GetMetadata(),
	}

	return result, nil
}

// BuildOptimizedFormat extracts problems into a central store and creates references.
// Returns: problemStore, problemRefs, optimizedFindings
func BuildOptimizedFormat(findings []testapi.FindingData) (map[string]json.RawMessage, map[string][]string, []testapi.FindingData) {
	problemStore := make(map[string]json.RawMessage)
	problemRefs := make(map[string][]string)
	optimizedFindings := make([]testapi.FindingData, len(findings))
	anonCounter := 0

	for i, finding := range findings {
		if finding.Attributes == nil || len(finding.Attributes.Problems) == 0 {
			optimizedFindings[i] = finding
			continue
		}

		// Extract problems and build references
		refs := make([]string, 0, len(finding.Attributes.Problems))
		for _, problem := range finding.Attributes.Problems {
			problemID := problem.GetID()
			if problemID == "" {
				// No ID - assign unique key
				problemID = fmt.Sprintf("_anon_%d", anonCounter)
				anonCounter++
			}

			// Add to store if not present
			if _, exists := problemStore[problemID]; !exists {
				if problemJSON, err := json.Marshal(problem); err == nil {
					problemStore[problemID] = problemJSON
				}
			}

			refs = append(refs, problemID)
		}

		// Store refs for this finding
		if finding.Id != nil && len(refs) > 0 {
			problemRefs[finding.Id.String()] = refs
		}

		// Create finding without problems
		optimizedFinding := finding
		if optimizedFinding.Attributes != nil {
			attrCopy := *optimizedFinding.Attributes
			attrCopy.Problems = nil // Remove problems from wire format
			optimizedFinding.Attributes = &attrCopy
		}
		optimizedFindings[i] = optimizedFinding
	}

	return problemStore, problemRefs, optimizedFindings
}

func NewSerializableTestResultFromBytes(jsonBytes []byte) ([]testapi.TestResult, error) {
	var tmp []jsonTestResult
	err := json.Unmarshal(jsonBytes, &tmp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal test result: %w", err)
	}

	testResults := make([]testapi.TestResult, len(tmp))
	for i := range tmp {
		testResults[i] = &tmp[i]
	}

	return testResults, nil
}

// ReconstructFindings rebuilds full findings from problemStore and problemRefs.
// It returns an error if any problems fail to reconstruct.
// After successful reconstruction, it clears the optimized data to free memory.
func ReconstructFindings(result *jsonTestResult) error {
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	// If already reconstructed, nothing to do
	if result.fullFindings != nil {
		return nil
	}

	fullFindings := make([]testapi.FindingData, len(result.FindingsData))
	var reconstructionErrors []string

	for i, finding := range result.FindingsData {
		fullFinding := finding

		// Reconstruct problems from references
		if finding.Id != nil && finding.Attributes != nil {
			if problemIDs, ok := result.ProblemRefs[finding.Id.String()]; ok {
				problems := make([]testapi.Problem, 0, len(problemIDs))
				for _, problemID := range problemIDs {
					if problemJSON, exists := result.ProblemStore[problemID]; exists {
						var problem testapi.Problem
						if err := json.Unmarshal(problemJSON, &problem); err != nil {
							reconstructionErrors = append(reconstructionErrors,
								fmt.Sprintf("failed to unmarshal problem %s: %v", problemID, err))
							continue
						}
						problems = append(problems, problem)
					} else {
						reconstructionErrors = append(reconstructionErrors,
							fmt.Sprintf("problem %s referenced but not found in problemStore", problemID))
					}
				}

				// Restore problems to attributes
				attrCopy := *fullFinding.Attributes
				attrCopy.Problems = problems
				fullFinding.Attributes = &attrCopy
			}
		}

		fullFindings[i] = fullFinding
	}

	// If there were errors, return them
	if len(reconstructionErrors) > 0 {
		return fmt.Errorf("reconstruction errors: %v", reconstructionErrors)
	}

	// Store reconstructed findings (with in-memory deduplication)
	deduplicateProblemsInFindings(fullFindings)
	result.fullFindings = fullFindings

	// Clear optimized data to free memory (no longer needed)
	result.ProblemStore = nil
	result.ProblemRefs = nil
	result.FindingsData = nil

	return nil
}

// deduplicateProblemsInFindings deduplicates problems across findings in memory.
func deduplicateProblemsInFindings(findings []testapi.FindingData) {
	problemCache := make(map[string]*testapi.Problem)

	for i := range findings {
		if findings[i].Attributes == nil || len(findings[i].Attributes.Problems) == 0 {
			continue
		}

		deduplicatedProblems := make([]testapi.Problem, 0, len(findings[i].Attributes.Problems))
		for j := range findings[i].Attributes.Problems {
			problem := &findings[i].Attributes.Problems[j]
			problemID := problem.GetID()

			if problemID != "" {
				if cached, exists := problemCache[problemID]; exists {
					deduplicatedProblems = append(deduplicatedProblems, *cached)
				} else {
					problemCache[problemID] = problem
					deduplicatedProblems = append(deduplicatedProblems, *problem)
				}
			} else {
				deduplicatedProblems = append(deduplicatedProblems, *problem)
			}
		}

		findings[i].Attributes.Problems = deduplicatedProblems
	}
}
