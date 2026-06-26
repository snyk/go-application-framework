package livecheck

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var workflowIDWhoAmI = workflow.NewWorkflowIdentifier("whoami")

type AuthStatus struct {
	OK           bool
	Identity     string
	ErrorMessage string
}

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

func (a AuthStatus) format() string {
	var sb strings.Builder
	sb.WriteString("\n\nAuthentication\n\n")
	if a.OK {
		fmt.Fprintf(&sb, "  Authenticated as: %s\n", a.Identity)
	} else {
		sb.WriteString("  Failed to verify authentication\n")
		fmt.Fprintf(&sb, "  Error: %s\n", a.ErrorMessage)
	}
	return sb.String()
}
