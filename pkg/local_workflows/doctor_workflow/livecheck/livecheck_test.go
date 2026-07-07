package livecheck

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	connectivitycheck "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/auth"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const sampleConnectivityJSON = `{
  "proxyConfig": {"detected": false},
  "hostResults": [
    {"host": "api.snyk.io", "status": 0},
    {"host": "app.snyk.io", "status": 1}
  ],
  "todos": [],
  "organizations": [
    {"slug": "my-org", "isDefault": true}
  ],
  "tokenPresent": true
}`

func TestRun(t *testing.T) {
	configOKFinding := diagnosis.Finding{
		Producer: diagnosis.ProducerConfig,
		Kind:     diagnosis.KindConfigOK,
		Severity: diagnosis.SeverityInfo,
		Message:  "No configuration issues detected",
	}
	authOKFinding := diagnosis.Finding{
		Producer: diagnosis.ProducerAuth,
		Kind:     diagnosis.KindAuthOK,
		Severity: diagnosis.SeverityInfo,
		Message:  "Successfully authenticated",
		Fields:   map[string]string{"user": "user@snyk.io"},
	}
	authFailFinding := diagnosis.Finding{
		Producer: diagnosis.ProducerAuth,
		Kind:     diagnosis.KindAuthFailure,
		Severity: diagnosis.SeverityError,
		Message:  "Failed to verify authentication",
		Details:  []string{"authentication error (status: 401)"},
	}
	connectivityOKFinding := diagnosis.Finding{
		Producer: diagnosis.ProducerConnectivity,
		Kind:     diagnosis.KindConnectivityOK,
		Severity: diagnosis.SeverityInfo,
		Message:  "Connection successfully verified",
		Fields: map[string]string{
			"proxy": "none detected",
			"hosts": "2/2 reachable",
		},
		Details: []string{
			"Organizations: 1",
			"my-org (default)",
		},
	}
	connectivityFailFinding := diagnosis.Finding{
		Producer: diagnosis.ProducerConnectivity,
		Kind:     diagnosis.KindConnectivityFailure,
		Severity: diagnosis.SeverityError,
		Message:  "Connection issues discovered",
		Details:  []string{"connectivity check failed"},
	}

	tests := []struct {
		name            string
		whoamiOut       []workflow.Data
		whoamiErr       error
		connectivityOut []workflow.Data
		connectivityErr error
		want            []diagnosis.Finding
	}{
		{
			name:            "both checks succeed",
			whoamiOut:       []workflow.Data{whoAmIData("user@snyk.io")},
			connectivityOut: []workflow.Data{connectivityData(sampleConnectivityJSON)},
			want:            []diagnosis.Finding{configOKFinding, authOKFinding, connectivityOKFinding},
		},
		{
			name:            "auth fails, connectivity succeeds",
			whoamiErr:       errors.New("authentication error (status: 401)"),
			connectivityOut: []workflow.Data{connectivityData(sampleConnectivityJSON)},
			want:            []diagnosis.Finding{configOKFinding, authFailFinding, connectivityOKFinding},
		},
		{
			name:            "auth succeeds, connectivity fails",
			whoamiOut:       []workflow.Data{whoAmIData("user@snyk.io")},
			connectivityErr: errors.New("connectivity check failed"),
			want:            []diagnosis.Finding{configOKFinding, authOKFinding, connectivityFailFinding},
		},
		{
			name:            "both checks fail",
			whoamiErr:       errors.New("authentication error (status: 401)"),
			connectivityErr: errors.New("connectivity check failed"),
			want:            []diagnosis.Finding{configOKFinding, authFailFinding, connectivityFailFinding},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			config := configuration.NewWithOpts()

			engine := mocks.NewMockEngine(ctrl)
			gomock.InOrder(
				engine.EXPECT().
					Invoke(auth.WhoAmIWorkflowID, gomock.Any(), gomock.Any()).
					Return(tt.whoamiOut, tt.whoamiErr),
				engine.EXPECT().
					InvokeWithConfig(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, gomock.Any()).
					Return(tt.connectivityOut, tt.connectivityErr),
			)

			// The auth check's credential pre-check adds auth headers; inject one
			// so it proceeds to the whoami call rather than short-circuiting.
			netAccess := mocks.NewMockNetworkAccess(ctrl)
			netAccess.EXPECT().AddHeaders(gomock.Any()).DoAndReturn(func(r *http.Request) error {
				r.Header.Set("Authorization", "token test")
				return nil
			}).AnyTimes()

			ctx := mocks.NewMockInvocationContext(ctrl)
			ctx.EXPECT().Context().Return(context.Background()).AnyTimes()
			ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
			ctx.EXPECT().GetEngine().Return(engine).AnyTimes()
			ctx.EXPECT().GetNetworkAccess().Return(netAccess).AnyTimes()

			actual := Run(ctx)
			// compare wanted findings vs actual and focus only on producer and severity
			for i, want := range tt.want {
				assert.Equal(t, want.Producer, actual[i].Producer)
				assert.Equal(t, want.Severity, actual[i].Severity)
			}
		})
	}
}

func whoAmIData(payload string) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(auth.WhoAmIWorkflowID, "whoami"),
		"text/plain",
		payload,
	)
}

func connectivityData(payload string) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, "connectivity-check"),
		"application/json",
		[]byte(payload),
	)
}
