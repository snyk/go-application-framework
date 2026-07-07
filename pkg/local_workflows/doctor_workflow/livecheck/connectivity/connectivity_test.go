package connectivity

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	connectivitycheck "github.com/snyk/go-application-framework/pkg/local_workflows/connectivity_check_extension"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
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

func TestCheckConnectivity(t *testing.T) {
	tests := []struct {
		name      string
		invokeOut []workflow.Data
		invokeErr error
		want      connectivityStatus
	}{
		{
			name:      "success",
			invokeOut: []workflow.Data{connectivityData(sampleConnectivityJSON)},
			want: connectivityStatus{
				Summary: connectivitySummary{
					Proxy:         "none detected",
					HostsOK:       2,
					HostsTotal:    2,
					TokenPresent:  true,
					OrgCount:      1,
					Organizations: []string{"my-org (default)"},
				},
			},
		},
		{
			name:      "invoke fails",
			invokeErr: errors.New("connectivity check failed"),
			want: connectivityStatus{
				Summary: connectivitySummary{Failed: true, FailureText: "connectivity check failed"},
			},
		},
		{
			name:      "empty result",
			invokeOut: []workflow.Data{},
			want: connectivityStatus{
				Summary: connectivitySummary{Failed: true, FailureText: "connectivity check returned no usable result"},
			},
		},
		{
			name:      "bad json",
			invokeOut: []workflow.Data{connectivityData("{")},
			want: connectivityStatus{
				Summary: connectivitySummary{Failed: true, FailureText: "could not decode connectivity result:"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			config := configuration.NewWithOpts()

			engine := mocks.NewMockEngine(ctrl)
			engine.EXPECT().
				InvokeWithConfig(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, gomock.Any()).
				Return(tt.invokeOut, tt.invokeErr)

			ctx := mocks.NewMockInvocationContext(ctrl)
			ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
			ctx.EXPECT().GetEngine().Return(engine).AnyTimes()

			got := Check(ctx)
			if tt.name == "bad json" {
				assert.True(t, got.Summary.Failed)
				assert.Contains(t, got.Summary.FailureText, "could not decode connectivity result:")
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConnectivityStatus_findings(t *testing.T) {
	ok := connectivityStatus{
		Summary: connectivitySummary{
			Proxy:         "none detected",
			HostsOK:       2,
			HostsTotal:    2,
			TokenPresent:  true,
			OrgCount:      1,
			Organizations: []string{"my-org (default)"},
		},
	}
	findings := ok.Findings()
	assert.Len(t, findings, 1)
	assert.Equal(t, diagnosis.ProducerConnectivity, findings[0].Producer)

	failed := connectivityStatus{
		Summary: connectivitySummary{Failed: true, FailureText: "network down"},
	}.Findings()
	assert.Equal(t, diagnosis.SeverityError, failed[0].Severity)
}

func TestSummarizeConnectivity_omitsRedundantFailureTODOs(t *testing.T) {
	const payload = `{
  "proxyConfig": {"detected": true, "url": "localhost", "variable": "HTTPS_PROXY"},
  "hostResults": [
    {"host": "api.snyk.io", "status": 5},
    {"host": "app.snyk.io", "status": 5}
  ],
  "todos": [
    {"level": 2, "message": "Connection to 'api.snyk.io' failed: Get \"https://api.snyk.io\": Connection refused. This may be a firewall..."},
    {"level": 1, "message": "Proxy requires 'Basic' authentication for 'api.snyk.io'."}
  ],
  "organizations": [],
  "tokenPresent": false
}`

	var result connectivityResult
	require.NoError(t, json.Unmarshal([]byte(payload), &result))

	summary := summarizeConnectivity(result)
	assert.Len(t, summary.FailureGroups, 1)
	assert.Equal(t, "BLOCKED", summary.FailureGroups[0].Status)
	assert.Equal(t, []string{"api.snyk.io", "app.snyk.io"}, summary.FailureGroups[0].Hosts)
	assert.Len(t, summary.Warnings, 1)
	assert.Contains(t, summary.Warnings[0], "Proxy requires")

	findings := connectivityStatus{Summary: summary}.Findings()
	require.Len(t, findings, 1)
	for _, detail := range findings[0].Details {
		assert.NotContains(t, detail, "Connection to 'api.snyk.io' failed")
	}
}

func connectivityData(payload string) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(connectivitycheck.WORKFLOWID_CONNECTIVITY_CHECK, "connectivity-check"),
		"application/json",
		[]byte(payload),
	)
}
