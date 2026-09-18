package presenters_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTOONSummary_EmptyScanners(t *testing.T) {
	t.Parallel()
	output := renderFindings(t, `[
		{"testConfiguration":{"scan_config":{"sca":{}}}},
		{"testConfiguration":{"scan_config":{"secrets":{}}}}
	]`)
	require.Contains(t, output, "sca_summary: 0 vulnerabilities found")
	require.Contains(t, output, "secrets_summary: 0 secrets found")
}

func TestTOONSummary_SCACounting(t *testing.T) {
	t.Parallel()
	// Grouping is per test result, so repeated IDs must share one result to merge.
	output := renderFindings(t, `[
				{"findings":[
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"repeated","severity":"high","is_fixable":true}]}},
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_license","id":"license","severity":"low"}]}},
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"repeated","severity":"critical"}]},
					 "relationships":{"fix":{"data":{"attributes":{"action":{"format":"upgrade_package_advice",
					 "upgrade_paths":[{"dependency_path":[{},{"name":"fixed","version":"2"}]},{"dependency_path":[{},{}]}]}}}}}},
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_license","id":"license","severity":"high"}]}},
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"critical","severity":"critical"}]}},
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"medium","severity":"medium"}]}},
					{"attributes":{"finding_type":"sca","rating":{"severity":"high"},"problems":[{"source":"snyk_vuln","id":"missing"}]}},
					{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"unknown","severity":"HIGH"}]}}
				]}
	]`)
	require.Contains(t, output, "sca_summary: 5 unique vulns (7 paths) | 1 critical 1 high 1 medium 1 low | 1 fixable")
	require.Contains(t, output, "sca[5]")
	require.NotContains(t, output, "secrets_summary:")
}

func TestTOONSummary_SecretsCounting(t *testing.T) {
	t.Parallel()
	output := renderFindings(t, `[
				{"findings":[
					{"attributes":{"finding_type":"secret","title":"repeated","rating":{"severity":"HIGH"}}},
					{"attributes":{"finding_type":"secrets","title":"repeated","rating":{"severity":"high"}}},
					{"attributes":{"finding_type":"secrets","rating":{"severity":"low"}}},
					{}
				]},
				{"findings":[
					{"attributes":{"finding_type":"secrets","rating":{"severity":"critical"}}},
					{"attributes":{"finding_type":"secrets","rating":{"severity":"medium"}}},
					{"attributes":{"finding_type":"secrets"}}
				]}
	]`)
	require.Contains(t, output, "secrets_summary: 4 secrets | 1 critical 1 high 1 medium 1 low")
	require.Contains(t, output, "secrets[4]")
	require.NotContains(t, output, "sca_summary:")
}

func TestTOONSummary_FailedAndPartialScans(t *testing.T) {
	t.Parallel()
	for _, scanner := range []struct {
		name, finding, emptySummary, partialSummary string
	}{
		{"sca", `{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"example","severity":"high"}]}}`,
			"0 vulnerabilities found", "1 unique vulns | 1 high | 0 fixable"},
		{"secrets", `{"attributes":{"finding_type":"secrets","rating":{"severity":"high"}}}`,
			"0 secrets found", "1 secrets | 1 high"},
	} {
		failed := fmt.Sprintf(`{"executionState":"errored","testConfiguration":{"scan_config":{%q:{}}},"warnings":[{"detail":"Incomplete scan"}]}`, scanner.name)
		empty := fmt.Sprintf(`{"executionState":"finished","testConfiguration":{"scan_config":{%q:{}}}}`, scanner.name)
		for _, tc := range []struct {
			name, input, summary string
		}{
			{"failed only", `[` + failed + `]`, ""},
			{"empty then failed", `[` + empty + `,` + failed + `]`, scanner.emptySummary},
			{"failed then empty", `[` + failed + `,` + empty + `]`, scanner.emptySummary},
			{"partial findings", `[{"executionState":"errored","findings":[` + scanner.finding + `],"warnings":[{"detail":"Incomplete scan"}]}]`, scanner.partialSummary},
		} {
			t.Run(fmt.Sprintf("%s/%s", scanner.name, tc.name), func(t *testing.T) {
				t.Parallel()
				output := renderFindings(t, tc.input)
				require.Contains(t, output, scanner.name+"_error: Scan failed.")
				require.Contains(t, output, "Incomplete scan")
				if tc.summary == "" {
					require.NotContains(t, output, scanner.name+"_summary:")
				} else {
					require.Contains(t, output, scanner.name+"_summary: "+tc.summary)
				}
			})
		}
	}
}
