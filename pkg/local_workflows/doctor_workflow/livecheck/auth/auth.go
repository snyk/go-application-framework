package auth

import (
	"context"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
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

	// authCheckTimeout bounds the live whoami call (via WithContext) so a hung
	// request degrades to a finding instead of blocking the already-computed report.
	authCheckTimeout = 15 * time.Second
)

// AuthStatus is the outcome of the live authentication check.
type AuthStatus struct {
	OK           bool
	Identity     string
	ErrorMessage string
}

// Check verifies authentication via the whoami workflow: a string result is
// the identity; error/empty is a failure. The call is bounded by authCheckTimeout
// via WithContext so a hung request cancels rather than blocking doctor.
func Check(invocationCtx workflow.InvocationContext) AuthStatus {
	ctx, cancel := context.WithTimeout(invocationCtx.Context(), authCheckTimeout)
	defer cancel()

	data, err := invocationCtx.GetEngine().Invoke(
		WhoAmIWorkflowID,
		workflow.WithConfig(whoamiConfig(invocationCtx.GetConfiguration())),
		workflow.WithContext(ctx),
	)
	if err != nil {
		return AuthStatus{ErrorMessage: err.Error()}
	}
	if len(data) == 0 {
		return AuthStatus{ErrorMessage: "whoami returned no usable result"}
	}
	identity, ok := data[0].GetPayload().(string)
	if !ok {
		return AuthStatus{ErrorMessage: "whoami returned an unexpected payload type"}
	}
	return AuthStatus{OK: true, Identity: identity}
}

// whoamiConfig clones the doctor config and forces json off so whoami returns
// its plain-string identity payload regardless of the doctor run's --json.
func whoamiConfig(base configuration.Configuration) configuration.Configuration {
	config := base.Clone()
	config.Set(whoamiJSONFlag, false)
	return config
}

// Findings maps the auth status into the generic contract (Source = auth).
func (a AuthStatus) Findings() []diagnosis.Finding {
	if a.OK {
		return []diagnosis.Finding{{
			Source:   diagnosis.SourceAuth,
			Kind:     diagnosis.KindAuth,
			Severity: diagnosis.SeverityInfo,
			Message:  "Successfully authenticated",
			Fields:   map[string]string{"user": a.Identity},
		}}
	}
	return []diagnosis.Finding{{
		Source:   diagnosis.SourceAuth,
		Kind:     diagnosis.KindAuth,
		Severity: diagnosis.SeverityError,
		Message:  "Failed to verify authentication",
		Details:  []string{a.ErrorMessage},
	}}
}
