// Package config implements a live check that runs configuration sanity checks
// and maps each issue into the shared diagnosis.Finding contract.
package config

import (
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ConfigStatus is the outcome of the configuration sanity check.
type ConfigStatus struct {
	Issues []string
}

// Check runs config_utils.CheckSanity and captures the results.
func Check(invocationCtx workflow.InvocationContext) ConfigStatus {
	results := config_utils.CheckSanity(invocationCtx.GetConfiguration())
	var issues []string
	for _, res := range results {
		issues = append(issues, res.Description)
	}
	return ConfigStatus{Issues: issues}
}

// Findings maps the config status into the generic Finding contract.
func (c ConfigStatus) Findings() []diagnosis.Finding {
	if len(c.Issues) == 0 {
		return []diagnosis.Finding{{
			Producer: diagnosis.ProducerConfig,
			Kind:     diagnosis.KindConfigOK,
			Severity: diagnosis.SeverityInfo,
			Message:  "No configuration issues detected",
		}}
	}

	var findings []diagnosis.Finding
	for _, issue := range c.Issues {
		findings = append(findings, diagnosis.Finding{
			Producer: diagnosis.ProducerConfig,
			Kind:     diagnosis.KindConfigCheck,
			Title:    "Possible configuration issue",
			Message:  issue,
			Severity: diagnosis.SeverityWarning,
		})
	}
	return findings
}
