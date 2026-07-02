package livecheck

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestCheckAuth(t *testing.T) {
	tests := []struct {
		name      string
		invokeOut []workflow.Data
		invokeErr error
		want      AuthStatus
	}{
		{
			name:      "authenticated",
			invokeOut: []workflow.Data{whoAmIData("user@snyk.io")},
			want:      AuthStatus{OK: true, Identity: "user@snyk.io"},
		},
		{
			name:      "whoami fails",
			invokeErr: errors.New("authentication error (status: 401)"),
			want:      AuthStatus{ErrorMessage: "authentication error (status: 401)"},
		},
		{
			name:      "empty result",
			invokeOut: []workflow.Data{},
			want:      AuthStatus{ErrorMessage: "whoami returned no usable result"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			config := configuration.NewWithOpts()

			engine := mocks.NewMockEngine(ctrl)
			engine.EXPECT().
				InvokeWithConfig(workflowIDWhoAmI, gomock.Any()).
				Return(tt.invokeOut, tt.invokeErr)

			ctx := mocks.NewMockInvocationContext(ctrl)
			ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
			ctx.EXPECT().GetEngine().Return(engine).AnyTimes()

			assert.Equal(t, tt.want, checkAuth(ctx))
		})
	}
}

func TestAuthStatus_finding(t *testing.T) {
	ok := AuthStatus{OK: true, Identity: "user@snyk.io"}.finding()
	assert.Equal(t, diagnosis.SourceAuth, ok.Source)
	assert.Equal(t, diagnosis.SeverityInfo, ok.Severity)
	assert.Contains(t, ok.Message, "user@snyk.io")
	assert.Equal(t, "user@snyk.io", ok.Fields["identity"])

	failed := AuthStatus{ErrorMessage: "Authentication error"}.finding()
	assert.Equal(t, diagnosis.SourceAuth, failed.Source)
	assert.Equal(t, diagnosis.SeverityError, failed.Severity)
	assert.Contains(t, failed.Message, "Failed to verify authentication")
	assert.Contains(t, failed.Details, "Authentication error")
}

func whoAmIData(payload string) workflow.Data {
	// whoami (without --json) returns the username as a plain string payload.
	return workflow.NewData(
		workflow.NewTypeIdentifier(workflowIDWhoAmI, "whoami"),
		"text/plain",
		payload,
	)
}
