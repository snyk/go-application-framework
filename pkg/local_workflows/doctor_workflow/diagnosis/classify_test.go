package diagnosis

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsFeatureFlag403(t *testing.T) {
	tests := []struct {
		name string
		f    Finding
		want bool
	}{
		{
			name: "feature-flag 403 by url",
			f:    Finding{Kind: KindCorrelation, Fields: map[string]string{FieldStatus: "403", FieldURL: "https://api.snyk.io/v1/cli-config/feature-flags/scanUsrLibJars?org=x"}},
			want: true,
		},
		{
			name: "feature-flag 403 by reason (no url attributed)",
			f:    Finding{Kind: KindCorrelation, Fields: map[string]string{FieldStatus: "403", FieldReason: "Org x doesn't have 'y' feature enabled"}},
			want: true,
		},
		{
			name: "edge-block 403 is not benign",
			f:    Finding{Kind: KindCorrelation, Fields: map[string]string{FieldStatus: "403", FieldURL: "https://api.snyk.io/v1/monitor-dependencies?org=x", FieldReason: "Access Denied (Akamai)"}},
			want: false,
		},
		{
			name: "401 is not benign",
			f:    Finding{Kind: KindCorrelation, Fields: map[string]string{FieldStatus: "401", FieldURL: "https://api.snyk.io/v1/cli-config/feature-flags/x"}},
			want: false,
		},
		{
			name: "non-correlation finding is not benign",
			f:    Finding{Kind: KindCLIError, Fields: map[string]string{FieldStatus: "403"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isFeatureFlag403(tt.f))
		})
	}
}

func TestAnalyze_dropsFeatureFlag403KeepsRealBlock(t *testing.T) {
	log := strings.Join([]string{
		// Benign: feature-flag probe returns 403.
		"2026-06-10T13:10:38Z main - > request [0x500]: GET https://api.snyk.io/v1/cli-config/feature-flags/scanUsrLibJars?org=x",
		"2026-06-10T13:10:38Z main - > request [0x500]: header: map[Snyk-Request-Id:[req-ff]]",
		"2026-06-10T13:10:38Z main - < response [0x640]: 403 Forbidden",
		"2026-06-10T13:10:38Z main - < response [0x640]: header: map[Snyk-Request-Id:[req-ff]]",
		`2026-06-10T13:10:38Z main - < response [0x640]: body: {"ok":false,"userMessage":"Org x doesn't have 'scan-usr-lib-jars' feature enabled"}`,
		// Real: a genuine 403 on a normal endpoint.
		"2026-06-10T13:10:38Z main - > request [0xaa0]: PUT https://api.snyk.io/v1/monitor-dependencies?org=x",
		"2026-06-10T13:10:38Z main - > request [0xaa0]: header: map[Snyk-Request-Id:[req-real]]",
		"2026-06-10T13:10:38Z main - < response [0xbb0]: 403 Forbidden",
		"2026-06-10T13:10:38Z main - < response [0xbb0]: header: map[Snyk-Request-Id:[req-real]]",
	}, "\n")

	report, err := Analyze(context.Background(), strings.NewReader(log), DefaultLogChecks())
	require.NoError(t, err)

	correlations := 0
	for _, f := range report.Findings {
		if f.Kind == KindCorrelation {
			correlations++
			assert.Contains(t, f.Fields[FieldURL], "monitor-dependencies", "only the non-feature-flag 403 should remain")
		}
	}
	assert.Equal(t, 1, correlations, "the feature-flag 403 must be filtered out")
}
