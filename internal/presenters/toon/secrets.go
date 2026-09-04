package toon

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// ProjectSecrets maps native UFM Secrets findings to the concise TOON view model.
func ProjectSecrets(results []testapi.TestResult) (SecretsView, error) {
	issues, err := issuesByFindingType(results, testapi.FindingTypeSecrets)
	if err != nil {
		return SecretsView{}, err
	}

	if len(issues) == 0 {
		return SecretsView{Summary: "0 secrets found"}, nil
	}

	counts := map[string]int{}
	rows := make([]SecretsRow, 0, len(issues))

	for _, issue := range issues {
		if issue.GetFindingType() != testapi.FindingTypeSecrets {
			continue
		}

		severity := strings.ToLower(issue.GetSeverity())
		if severity == "" {
			severity = "low"
		}
		counts[severity]++

		file := "unknown"
		line := 0
		if locs := issue.GetSourceLocations(); len(locs) > 0 {
			if locs[0].FilePath != "" {
				file = locs[0].FilePath
			}
			line = locs[0].FromLine
		}

		rows = append(rows, SecretsRow{
			Rule:     secretsRule(issue),
			Severity: severity,
			File:     file,
			Line:     line,
		})
	}

	return SecretsView{
		Rows:    rows,
		Summary: secretsSummary(len(rows), counts),
	}, nil
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
