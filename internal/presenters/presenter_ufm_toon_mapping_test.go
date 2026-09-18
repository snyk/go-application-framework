package presenters_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func TestTOONMapping_SCAOccurrences(t *testing.T) {
	t.Parallel()

	output := renderFindings(t, `[
		{"findings": [{"attributes": {
			"finding_type": "sca", "title": "not selected", "rating": {"severity": "low"},
			"problems": [{"source": "snyk_vuln", "id": "SNYK-EXAMPLE-1", "severity": "high", "is_fixable": true}],
			"locations": [{"type": "package", "package": {"name": "example", "version": "1.10"}}]
		}}]},
		{"findings": [{"attributes": {
			"finding_type": "sca", "rating": {"severity": "medium"},
			"problems": [{"source": "snyk_vuln", "id": "SNYK-EXAMPLE-1", "severity": "medium"}],
			"locations": [{"type": "package", "package": {"name": "example", "version": "1.2"}}]
		}}]}
	]`)
	requireTOONEqual(t, `sca[2]{fixable,id,pkg,severity}:
  no,SNYK-EXAMPLE-1,example@1.10,high
  no,SNYK-EXAMPLE-1,example@1.2,medium
sca_summary: 2 unique vulns | 1 high 1 medium | 0 fixable`, output)
}

func TestTOONMapping_GroupedSCAVersions(t *testing.T) {
	t.Parallel()

	output := renderFindings(t, `[{"findings":[
		{"attributes":{"finding_type":"sca","rating":{"severity":"high"},
			"problems":[{"source":"snyk_vuln","id":"same","severity":"high","package_name":"example","package_version":"1.10"}]}},
		{"attributes":{"finding_type":"sca","rating":{"severity":"medium"},
			"problems":[{"source":"snyk_vuln","id":"same","severity":"medium","package_name":"example","package_version":"1.2"}]}}
	]}]`)
	requireTOONEqual(t, `sca[1]{fixable,id,pkg,severity}:
  no,same,"example@1.10,1.2",high
sca_summary: 1 unique vulns (2 paths) | 1 high | 0 fixable`, output)
}

func TestTOONMapping_SecretsFallbacks(t *testing.T) {
	t.Parallel()

	output := renderFindings(t, `[{"findings": [
		{"attributes": {"finding_type":"secrets", "title":"fallback", "rating":{"severity":"high"},
			"problems":[{"source":"cwe","id":"CWE-798"},{"source":"secret","id":"rule-1"},{"id":"rule-2"}],
			"locations":[{"type":"source","file_path":"first.txt","from_line":7,"to_line":10},
				{"type":"source","file_path":"second.txt","from_line":12}]}},
		{"attributes": {"finding_type":"secrets", "title":"fallback", "key":"finding-b", "rating":{"severity":"low"}}},
		{"attributes": {"finding_type":"secrets", "key":"finding-a", "rating":{"severity":"low"},
			"locations":[{"type":"source","from_line":"invalid"}]}},
		{}
	]}]`)
	requireTOONEqual(t, `secrets[3]{file,line,rule,severity}:
  first.txt,7,rule-1,high
  unknown,0,secret,low
  unknown,0,fallback,low
secrets_summary: 3 secrets | 1 high 2 low`, output)
}

func TestTOONMapping_SortedBySeverity(t *testing.T) {
	t.Parallel()
	output := renderFindings(t, `[{"findings":[
		{"attributes":{"finding_type":"sca","rating":{"severity":"low"},"problems":[{"source":"snyk_vuln","id":"a-low","severity":"low"}]}},
		{"attributes":{"finding_type":"sca","rating":{"severity":"critical"},"problems":[{"source":"snyk_vuln","id":"b-critical","severity":"critical"}]}}
	]}]`)
	requireTOONEqual(t, `sca[2]{fixable,id,pkg,severity}:
  no,b-critical,@,critical
  no,a-low,@,low
sca_summary: 2 unique vulns | 1 critical 1 low | 0 fixable`, output)
}

func TestTOONMapping_FiltersByEffectiveSeverity(t *testing.T) {
	t.Parallel()
	output := renderFindingsWithOptions(t, `[{"findings":[
		{"attributes":{"finding_type":"sca","rating":{"severity":"high"},
			"policy_modifications":[{"pointer":"/rating/severity","prior":"low"}],
			"problems":[{"source":"snyk_vuln","id":"effective-high","severity":"low"}]}},
		{"attributes":{"finding_type":"sca","rating":{"severity":"low"},
			"policy_modifications":[{"pointer":"/rating/severity","prior":"high"}],
			"problems":[{"source":"snyk_vuln","id":"effective-low","severity":"high"}]}}
	]}]`, "high", false)
	requireTOONEqual(t, `sca[1]{fixable,id,pkg,severity}:
  no,effective-high,@,low
sca_summary: 1 unique vulns | 1 low | 0 fixable`, output)
}

func TestTOONMapping_OrdersActiveBeforeConfiguredIgnoredIssues(t *testing.T) {
	t.Parallel()
	input := `[{"findings":[
		{"attributes":{"finding_type":"secrets","title":"active-low","rating":{"severity":"low"}}},
		{"attributes":{"finding_type":"secrets","title":"ignored-critical","rating":{"severity":"critical"},"suppression":{"status":"ignored"}}},
		{"attributes":{"finding_type":"secrets","title":"active-high","rating":{"severity":"high"}}},
		{"attributes":{"finding_type":"secrets","title":"ignored-medium","rating":{"severity":"medium"},"suppression":{"status":"ignored"}}}
	]}]`

	requireTOONEqual(t, `secrets[2]{file,line,rule,severity}:
  unknown,0,active-high,high
  unknown,0,active-low,low
secrets_summary: 2 secrets | 1 high 1 low`, renderFindingsWithOptions(t, input, "", false))
	requireTOONEqual(t, `secrets[4]{file,line,rule,severity}:
  unknown,0,active-high,high
  unknown,0,active-low,low
  unknown,0,ignored-critical,critical
  unknown,0,ignored-medium,medium
secrets_summary: 4 secrets | 1 critical 1 high 1 medium 1 low`, renderFindingsWithOptions(t, input, "", true))
}

func TestTOONMapping_FilteredIssuesRetainDiagnostics(t *testing.T) {
	t.Parallel()
	output := renderFindingsWithOptions(t, `[{
		"testConfiguration":{"scan_config":{"secrets":{}}},
		"errors":[{"detail":"partial failure"}],"warnings":[{"detail":"partial warning"}],
		"findings":[
			{"attributes":{"finding_type":"secrets","title":"ignored","rating":{"severity":"high"},"suppression":{"status":"ignored"}}},
			{"attributes":{"finding_type":"secrets","title":"low","rating":{"severity":"low"}}}
		]
	}]`, "high", false)
	require.Contains(t, output, "hint: add --toon=full for all fields")
	require.Contains(t, output, "secrets: []")
	require.Contains(t, output, "secrets_error: partial failure")
	require.Contains(t, output, "secrets_hint: partial warning")
	require.NotContains(t, output, "unknown,0,")
}

func TestTOONMapping_StableVersions(t *testing.T) {
	var findings []string
	for _, version := range []string{"1.0", "01.0", "1.0"} {
		findings = append(findings, fmt.Sprintf(`{"attributes":{"finding_type":"sca","rating":{"severity":"low"},
			"problems":[{"source":"snyk_vuln","id":"same","package_name":"example","package_version":%q}]}}`, version))
	}
	output := renderFindings(t, `[{"findings":[`+strings.Join(findings, ",")+`]}]`)
	requireTOONEqual(t, `sca[1]{fixable,id,pkg,severity}:
  no,same,"example@01.0,1.0",""
sca_summary: 1 unique vulns (3 paths) |  | 0 fixable`, output)
}

func TestTOONMapping_SCAFixability(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, action, expected string
		fixable                int
	}{
		{"upgrade", `{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{"name":"root","version":"1"},{"name":"example","version":"2"}]}]}`, "yes", 1},
		{"root only", `{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{"name":"root","version":"1"}],"is_drop":true}]}`, "no", 0},
		{"empty target", `{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{},{}]}]}`, "yes", 1},
		{"pin", `{"format":"pin_package_advice","package_name":"example","pin_version":"2"}`, "yes", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := renderFindings(t, fmt.Sprintf(`[{"findings":[
				{"attributes":{"finding_type":"sca","rating":{"severity":"low"},"problems":[{"source":"snyk_vuln","id":"same","is_fixable":true}]}},
				{"attributes":{"finding_type":"sca","rating":{"severity":"low"},"problems":[{"source":"snyk_vuln","id":"same"}]},
				 "relationships":{"fix":{"data":{"attributes":{"action":%s}}}}}
			]}]`, tc.action))
			requireTOONEqual(t, fmt.Sprintf(`sca[1]{fixable,id,pkg,severity}:
  %s,same,@,""
sca_summary: 1 unique vulns (2 paths) |  | %d fixable`, tc.expected, tc.fixable), output)
		})
	}
}

func TestTOONMapping_SCASources(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, attributes, expected, severity string
	}{
		{
			"prefer first vulnerability over license and other identifiers",
			`"rating":{"severity":"low"},"problems":[{"source":"snyk_license","id":"license"},{"source":"cve","id":"CVE-EXAMPLE"},
				{"source":"snyk_vuln","id":"first","severity":"high","package_name":"fallback","package_version":"3"},
				{"source":"snyk_vuln","id":"second","severity":"low"}],
			 "locations":[{"type":"source","file_path":"manifest"},{"type":"package","package":{"name":"installed","version":"2"}}]`,
			`no,first,installed@2,high`, "1 high",
		},
		{
			"license package fallback",
			`"rating":{"severity":"low"},"problems":[{"source":"snyk_license","id":"snyk:lic:npm:x:MIT","severity":"medium","package_name":"example","package_version":"3"}]`,
			`no,"snyk:lic:npm:x:MIT",example@3,medium`, "1 medium",
		},
		{
			"null fields retain empty defaults",
			`"rating":{"severity":"low"},"problems":[{"source":"snyk_vuln","id":null,"severity":null,"package_name":null,"package_version":null}]`,
			`no,"",@,""`, "",
		},
		{
			"empty ID and severity do not use finding fallbacks",
			`"key":"finding-key","rating":{"severity":"high"},"problems":[{"source":"snyk_vuln","package_name":"example","package_version":"3"}],
			 "locations":[{"type":"package","package":{"name":"installed"}}]`,
			`no,"",installed@3,""`, "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := renderFindings(t, fmt.Sprintf(
				`[{"findings":[{"attributes":{"finding_type":"sca",%s}}]}]`, tc.attributes))
			requireTOONEqual(t, "sca[1]{fixable,id,pkg,severity}:\n  "+tc.expected+
				"\nsca_summary: 1 unique vulns | "+tc.severity+" | 0 fixable", output)
		})
	}
}

func TestTOONMapping_MalformedSCA(t *testing.T) {
	t.Parallel()
	for _, attributes := range []string{
		`"problems":[{"source":"future_problem"}]`,
		`"problems":[{"source":42}]`,
		`"problems":[{"source":"snyk_vuln","id":42}]`,
		`"problems":[{"source":"snyk_vuln"}],"locations":[{"type":"package","package":"invalid"}]`,
	} {
		results, err := ufm.NewSerializableTestResultFromBytes([]byte(fmt.Sprintf(
			`[{"findings":[{"attributes":{"finding_type":"sca","rating":{"severity":"low"},%s}}]}]`, attributes)))
		require.NoError(t, err)
		value, err := renderTOONResults(t, results)
		require.Error(t, err)
		require.Empty(t, value)
	}
}

func renderFindings(t *testing.T, input string) string {
	t.Helper()
	return renderFindingsWithConfig(t, input, configuration.NewWithOpts())
}

func renderFindingsWithOptions(t *testing.T, input, threshold string, includeIgnores bool) string {
	t.Helper()
	config := configuration.NewWithOpts()
	config.Set(configuration.FLAG_SEVERITY_THRESHOLD, threshold)
	config.Set(configuration.FLAG_INCLUDE_IGNORES, includeIgnores)
	return renderFindingsWithConfig(t, input, config)
}

func renderFindingsWithConfig(t *testing.T, input string, config configuration.Configuration) string {
	t.Helper()
	results, err := ufm.NewSerializableTestResultFromBytes([]byte(input))
	require.NoError(t, err)
	var buffer bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &buffer)
	err = presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.NoError(t, err)
	return buffer.String()
}

func TestTOONMapping_UnfinishedScan(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"pending", "started"} {
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/complete=%t", state, complete), func(t *testing.T) {
				t.Parallel()
				results, err := ufm.NewSerializableTestResultFromBytes([]byte(fmt.Sprintf(
					`[{"executionState":%q,"findingsComplete":%t,"testConfiguration":{"scan_config":{"sca":{}}}}]`, state, complete)))
				require.NoError(t, err)
				envelope, err := renderTOONResults(t, results)
				require.ErrorContains(t, err, "scan is "+state)
				require.Empty(t, envelope)
			})
		}
	}
}

func renderTOONResults(t *testing.T, results []testapi.TestResult) (string, error) {
	t.Helper()
	config := configuration.NewWithOpts()
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output)
	err := presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	return output.String(), err
}

func requireTOONEqual(t *testing.T, rows, output string) {
	t.Helper()
	header := "hint: add --toon=full for all fields\norg: unknown\nproject: unknown\n"
	require.Equal(t, header+rows, output)
}
