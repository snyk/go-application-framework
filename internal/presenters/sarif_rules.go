package presenters

import "github.com/snyk/go-application-framework/pkg/apiclients/testapi"

type sarifRuleReference struct {
	ID      string
	FromCWE bool
}

func sarifRuleForIssue(issue testapi.Issue) sarifRuleReference {
	if id := issue.GetProblemID(); id != "" {
		return sarifRuleReference{ID: id}
	}

	// Rift returns problem entries with source "cwe". The issue builder exposes
	// those IDs through GetCWEs() and leaves GetProblemID() empty. Use the CWE ID
	// here so the SARIF result can reference a rule.
	if issue.GetFindingType() == testapi.FindingTypeRift {
		if cwes := issue.GetCWEs(); len(cwes) > 0 {
			return sarifRuleReference{ID: cwes[0], FromCWE: true}
		}
	}
	return sarifRuleReference{}
}
