package toon

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

var secretsColumns = []colSpec[testapi.Issue]{
	{Name: "rule", Quoted: true, Value: secretsRule},
	{Name: "severity", Quoted: true, Value: normalizedSeverity},
	{Name: "file", Quoted: true, Value: issueFile},
	{Name: "line", Quoted: false, Value: issueLine},
}

// ProjectSecrets maps native UFM Secrets findings to the concise TOON section.
func ProjectSecrets(results []testapi.TestResult) (Section, error) {
	issues, err := issuesByFindingType(results, testapi.FindingTypeSecrets)
	if err != nil {
		return Section{}, err
	}

	filtered := make([]testapi.Issue, 0, len(issues))
	for _, issue := range issues {
		if issue.GetFindingType() == testapi.FindingTypeSecrets {
			filtered = append(filtered, issue)
		}
	}

	if len(filtered) == 0 {
		return buildSection("secrets", filtered, secretsColumns, "0 secrets found"), nil
	}

	counts := map[string]int{}
	for _, issue := range filtered {
		counts[normalizedSeverity(issue)]++
	}

	return buildSection("secrets", filtered, secretsColumns, secretsSummary(len(filtered), counts)), nil
}

func normalizedSeverity(issue testapi.Issue) string {
	severity := strings.ToLower(issue.GetSeverity())
	if severity == "" {
		return "low"
	}
	return severity
}

func issueFile(issue testapi.Issue) string {
	if locs := issue.GetSourceLocations(); len(locs) > 0 && locs[0].FilePath != "" {
		return locs[0].FilePath
	}
	return "unknown"
}

func issueLine(issue testapi.Issue) string {
	if locs := issue.GetSourceLocations(); len(locs) > 0 {
		return strconv.Itoa(locs[0].FromLine)
	}
	return "0"
}

func secretsRule(issue testapi.Issue) string {
	for _, problem := range issue.GetProblems() {
		secretsProblem, err := problem.AsSecretsRuleProblem()
		if err == nil && secretsProblem.Id != "" {
			return secretsProblem.Id
		}
	}

	if short, ok := issue.GetData(testapi.DataKeyRuleShortDescription); ok {
		if description, ok := short.(string); ok && description != "" {
			return description
		}
	}

	if title := issue.GetTitle(); title != "" {
		return title
	}
	return "secret"
}

func secretsSummary(total int, counts map[string]int) string {
	if total == 0 {
		return "0 secrets found"
	}

	var parts []string
	for _, severity := range scaSeverityOrder {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}
	return fmt.Sprintf("%d secrets | %s", total, strings.Join(parts, " "))
}

func issuesByFindingType(results []testapi.TestResult, findingType testapi.FindingType) ([]testapi.Issue, error) {
	var all []testapi.Issue
	for _, result := range results {
		issues, err := testapi.GetIssuesFromTestResult(result, []testapi.FindingType{findingType})
		if err != nil {
			return nil, err
		}
		all = append(all, issues...)
	}
	return all, nil
}
