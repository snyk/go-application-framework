// Package livecheck runs live, environment-touching diagnostics (auth now,
// connectivity later) and maps each into the shared diagnosis.Finding contract,
// so live results join the same findings stream as log analysis.
package livecheck

import (
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Run executes the live checks and returns their findings for inclusion in the
// doctor report. New checks append their findings here.
func Run(invocationCtx workflow.InvocationContext) []diagnosis.Finding {
	return append(
		[]diagnosis.Finding{checkAuth(invocationCtx).finding()},
		checkConnectivity(invocationCtx).findings()...,
	)
}
