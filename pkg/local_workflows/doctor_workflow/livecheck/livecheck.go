// Package livecheck runs live, environment-touching diagnostics (auth and
// connectivity) and maps each into the shared diagnosis.Finding contract,
// so live results join the same findings stream as log analysis.
package livecheck

import (
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/auth"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/cache"
	configcheck "github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/config"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/connectivity"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Run executes the live checks and returns their findings for inclusion in the
// doctor report. New checks append their findings here.
func Run(invocationCtx workflow.InvocationContext) []diagnosis.Finding {
	var findings []diagnosis.Finding
	findings = append(findings, configcheck.Check(invocationCtx).Findings()...)
	findings = append(findings, auth.Check(invocationCtx).Findings()...)
	findings = append(findings, connectivity.Check(invocationCtx).Findings()...)
	findings = append(findings, cache.Check(invocationCtx).Findings()...)
	return findings
}
