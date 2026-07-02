package livecheck

import (
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var workflowIDWhoAmI = workflow.NewWorkflowIdentifier("whoami")

// AuthStatus is the outcome of the live authentication check.
type AuthStatus struct {
	OK           bool
	Identity     string
	ErrorMessage string
}

// checkAuth verifies authentication by invoking the whoami workflow: a string
// result is the identity; any error or empty result is a failure.
func checkAuth(invocationCtx workflow.InvocationContext) AuthStatus {
	config := invocationCtx.GetConfiguration().Clone()

	data, err := invocationCtx.GetEngine().InvokeWithConfig(workflowIDWhoAmI, config)
	if err != nil {
		return AuthStatus{ErrorMessage: err.Error()}
	}
	if len(data) == 0 {
		return AuthStatus{ErrorMessage: "whoami returned no usable result"}
	}
	identity, ok := data[0].GetPayload().(string)
	if !ok {
		return AuthStatus{ErrorMessage: "whoami returned no usable result"}
	}
	return AuthStatus{OK: true, Identity: identity}
}

// finding maps the auth status into the generic contract (Source = auth).
func (a AuthStatus) finding() diagnosis.Finding {
	if a.OK {
		return diagnosis.Finding{
			Source:   diagnosis.SourceAuth,
			Kind:     "auth",
			Severity: diagnosis.SeverityInfo,
			Message:  "Authenticated as " + a.Identity,
			Fields:   map[string]string{"identity": a.Identity},
		}
	}
	return diagnosis.Finding{
		Source:   diagnosis.SourceAuth,
		Kind:     "auth",
		Severity: diagnosis.SeverityError,
		Message:  "Failed to verify authentication",
		Details:  []string{a.ErrorMessage},
	}
}
