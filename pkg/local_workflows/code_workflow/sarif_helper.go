package code_workflow

import (
	"slices"
	"strings"

	"github.com/snyk/code-client-go/sarif"
)

func filterSarifResultsByCategory(result *sarif.SarifResponse, categoryFilter []string) {
	if len(categoryFilter) == 0 {
		return
	}

	for i := range categoryFilter {
		categoryFilter[i] = strings.ToLower(categoryFilter[i])
	}

	for i := range result.Sarif.Runs {
		run := &result.Sarif.Runs[i]
		tmpRules := run.Tool.Driver.Rules
		tmpResults := run.Results
		run.Results = []sarif.Result{}
		run.Tool.Driver.Rules = []sarif.Rule{}

		for _, rule := range tmpRules {
			numberOfResultsForRule := 0
			categoryMatch := false

			for _, category := range rule.Properties.Categories {
				categoryMatch = slices.Contains(categoryFilter, strings.ToLower(category))
				if categoryMatch {
					break
				}
			}

			if !categoryMatch {
				continue
			}

			for _, r := range tmpResults {
				ruleId := r.RuleID
				if rule.ID == ruleId {
					run.Results = append(run.Results, r)
					numberOfResultsForRule++
				}
			}

			if numberOfResultsForRule > 0 {
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			}
		}
	}
}
