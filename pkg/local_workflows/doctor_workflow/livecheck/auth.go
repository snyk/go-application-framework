package livecheck

import (
	"time"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// WhoAmIWorkflowID is the whoami workflow this check invokes. It's re-derived
// from the name (not imported from localworkflows) to avoid an import cycle;
// whoami_id_test.go pins it to the canonical constant to prevent drift.
var WhoAmIWorkflowID = workflow.NewWorkflowIdentifier("whoami")

const (
	// whoamiJSONFlag is the whoami config flag that switches its payload from a
	// plain-string identity to a JSON []byte. We force it off so the string
	// contract below holds even when the doctor run itself used --json.
	whoamiJSONFlag = "json"

	// authCheckTimeout bounds the live whoami call so a hung request degrades to
	// a finding instead of blocking the already-computed report.
	authCheckTimeout = 15 * time.Second
)

// AuthStatus is the outcome of the live authentication check.
type AuthStatus struct {
	OK           bool
	Identity     string
	ErrorMessage string
}

// checkAuth verifies authentication via the whoami workflow: a string result is
// the identity; error/empty is a failure. Bounded by authCheckTimeout so a hung
// call can't block doctor (InvokeWithConfig takes no context).
func checkAuth(invocationCtx workflow.InvocationContext) AuthStatus {
	config := invocationCtx.GetConfiguration().Clone()
	// Force whoami's string-payload path regardless of the doctor run's --json.
	config.Set(whoamiJSONFlag, false)

	type invokeResult struct {
		data []workflow.Data
		err  error
	}
	resultCh := make(chan invokeResult, 1)
	go func() {
		data, err := invocationCtx.GetEngine().InvokeWithConfig(WhoAmIWorkflowID, config)
		resultCh <- invokeResult{data: data, err: err}
	}()

	select {
	case <-time.After(authCheckTimeout):
		return AuthStatus{ErrorMessage: "authentication check timed out"}
	case result := <-resultCh:
		if result.err != nil {
			return AuthStatus{ErrorMessage: result.err.Error()}
		}
		if len(result.data) == 0 {
			return AuthStatus{ErrorMessage: "whoami returned no usable result"}
		}
		identity, ok := result.data[0].GetPayload().(string)
		if !ok {
			return AuthStatus{ErrorMessage: "whoami returned an unexpected payload type"}
		}
		return AuthStatus{OK: true, Identity: identity}
	}
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
