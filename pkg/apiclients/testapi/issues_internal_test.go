package testapi

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSnykID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected bool
	}{
		// Valid Snyk IDs
		{"uppercase with hyphen", "SNYK-JS-LODASH-590103", true},
		{"lowercase with hyphen", "snyk-js-lodash-590103", true},
		{"mixed case with hyphen", "Snyk-JS-LODASH-590103", true},
		{"uppercase with colon", "SNYK:LIC:NPM:PACKAGE:MPL-2.0", true},
		{"lowercase with colon", "snyk:lic:npm:shescape:MPL-2.0", true},
		{"mixed case with colon", "Snyk:lic:npm:package:MIT", true},
		{"just snyk", "snyk", true},
		{"snyk with no delimiter", "snyktest", true},

		// Invalid/non-Snyk IDs
		{"CVE", "CVE-2021-1234", false},
		{"CWE", "CWE-89", false},
		{"GHSA", "GHSA-xxxx-yyyy-zzzz", false},
		{"starts with sn", "sny", false},
		{"empty string", "", false},
		{"short string", "sn", false},
		{"similar but not snyk", "snack-test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSnykID(tt.id)
			assert.Equal(t, tt.expected, result, "isSnykID(%q) = %v, want %v", tt.id, result, tt.expected)
		})
	}
}

func TestIdBasedIssueGrouper_ExtractProblemID(t *testing.T) {
	grouper := &idBasedIssueGrouper{}

	t.Run("prefers SNYK- ID over CVE", func(t *testing.T) {
		finding := &FindingData{
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Problems: []Problem{
					createProblem(t, "CVE-2021-1234", "cve"),
					createProblem(t, "SNYK-JS-LODASH-590103", "snyk_vuln"),
					createProblem(t, "CWE-89", "cwe"),
				},
			},
		}

		id := grouper.extractProblemID(finding)
		assert.Equal(t, "SNYK-JS-LODASH-590103", id)
	})

	t.Run("prefers snyk: ID over CVE", func(t *testing.T) {
		finding := &FindingData{
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Problems: []Problem{
					createProblem(t, "CVE-2021-1234", "cve"),
					createProblem(t, "snyk:lic:npm:shescape:MPL-2.0", "snyk_license"),
					createProblem(t, "CWE-89", "cwe"),
				},
			},
		}

		id := grouper.extractProblemID(finding)
		assert.Equal(t, "snyk:lic:npm:shescape:MPL-2.0", id)
	})

	t.Run("returns first Snyk ID when multiple exist", func(t *testing.T) {
		finding := &FindingData{
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Problems: []Problem{
					createProblem(t, "SNYK-JS-FIRST-123456", "snyk_vuln"),
					createProblem(t, "SNYK-JS-SECOND-789012", "snyk_vuln"),
				},
			},
		}

		id := grouper.extractProblemID(finding)
		assert.Equal(t, "SNYK-JS-FIRST-123456", id)
	})

	t.Run("falls back to CVE when no Snyk ID", func(t *testing.T) {
		finding := &FindingData{
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Problems: []Problem{
					createProblem(t, "CVE-2021-1234", "cve"),
					createProblem(t, "CWE-89", "cwe"),
				},
			},
		}

		id := grouper.extractProblemID(finding)
		assert.Equal(t, "CVE-2021-1234", id)
	})

	t.Run("handles mixed case Snyk ID", func(t *testing.T) {
		finding := &FindingData{
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Problems: []Problem{
					createProblem(t, "CVE-2021-1234", "cve"),
					createProblem(t, "Snyk-JS-LODASH-590103", "snyk_vuln"),
				},
			},
		}

		id := grouper.extractProblemID(finding)
		assert.Equal(t, "Snyk-JS-LODASH-590103", id)
	})

	t.Run("returns empty string when no problems", func(t *testing.T) {
		finding := &FindingData{
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Problems:    []Problem{},
			},
		}

		id := grouper.extractProblemID(finding)
		assert.Empty(t, id)
	})

	t.Run("falls back to unique key when no problem IDs", func(t *testing.T) {
		findingID := uuid.New()
		finding := &FindingData{
			Id: &findingID,
			Attributes: &FindingAttributes{
				FindingType: FindingTypeSca,
				Key:         "test-key",
				Problems:    []Problem{},
			},
		}

		// extractProblemID returns empty, but grouping logic will use getUniqueKey
		id := grouper.extractProblemID(finding)
		assert.Empty(t, id)

		// Verify getUniqueKey works
		uniqueKey := grouper.getUniqueKey(finding)
		assert.Equal(t, findingID.String(), uniqueKey)
	})
}

func TestIdBasedIssueGrouper_GroupFindings(t *testing.T) {
	grouper := &idBasedIssueGrouper{}

	t.Run("groups findings with same Snyk ID", func(t *testing.T) {
		findings := []*FindingData{
			{
				Attributes: &FindingAttributes{
					FindingType: FindingTypeSca,
					Key:         "finding-1",
					Problems: []Problem{
						createProblem(t, "SNYK-JS-LODASH-590103", "snyk_vuln"),
					},
				},
			},
			{
				Attributes: &FindingAttributes{
					FindingType: FindingTypeSca,
					Key:         "finding-2",
					Problems: []Problem{
						createProblem(t, "SNYK-JS-LODASH-590103", "snyk_vuln"),
					},
				},
			},
			{
				Attributes: &FindingAttributes{
					FindingType: FindingTypeSca,
					Key:         "finding-3",
					Problems: []Problem{
						createProblem(t, "SNYK-JS-OTHER-999999", "snyk_vuln"),
					},
				},
			},
		}

		groups := grouper.groupFindings(findings)
		assert.Len(t, groups, 2, "Should have 2 groups")

		// Verify one group has 2 findings, the other has 1
		var groupSizes []int
		for _, group := range groups {
			groupSizes = append(groupSizes, len(group))
		}
		assert.Contains(t, groupSizes, 2)
		assert.Contains(t, groupSizes, 1)
	})

	t.Run("prefers Snyk ID even when problems are in different order", func(t *testing.T) {
		findings := []*FindingData{
			{
				Attributes: &FindingAttributes{
					FindingType: FindingTypeSca,
					Problems: []Problem{
						createProblem(t, "CVE-2021-1234", "cve"),
						createProblem(t, "SNYK-JS-LODASH-590103", "snyk_vuln"),
					},
				},
			},
			{
				Attributes: &FindingAttributes{
					FindingType: FindingTypeSca,
					Problems: []Problem{
						createProblem(t, "SNYK-JS-LODASH-590103", "snyk_vuln"),
						createProblem(t, "CVE-2021-1234", "cve"),
					},
				},
			},
		}

		groups := grouper.groupFindings(findings)
		assert.Len(t, groups, 1, "Should group both findings together by Snyk ID")
		assert.Len(t, groups[0], 2, "Group should contain both findings")
	})
}

// Helper function to create a problem with an ID for testing
func createProblem(t *testing.T, id, source string) Problem {
	t.Helper()
	var problem Problem
	problemJSON := fmt.Sprintf(`{"id": "%s", "source": "%s"}`, id, source)
	err := json.Unmarshal([]byte(problemJSON), &problem)
	require.NoError(t, err)
	return problem
}
