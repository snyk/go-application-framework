package livecheck

import (
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type Checks struct {
	Auth AuthStatus
}

func Run(invocationCtx workflow.InvocationContext) Checks {
	return Checks{
		Auth: checkAuth(invocationCtx),
	}
}

func (c Checks) Format() string {
	return c.Auth.format()
}
