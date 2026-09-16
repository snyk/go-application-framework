package presenters_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/internal/presenters/toon"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func TestTOONMapping_SCAOccurrences(t *testing.T) {
	t.Parallel()

	output := renderFindings(t, false, `[
		{"findings": [{"attributes": {
			"finding_type": "sca", "title": "not selected", "rating": {"severity": "low"},
			"problems": [{"source": "snyk_vuln", "id": "SNYK-EXAMPLE-1", "severity": "high", "is_fixable": true}],
			"locations": [{"type": "package", "package": {"name": "example", "version": "1.10"}}]
		}}]},
		{"findings": [{"attributes": {
			"finding_type": "sca",
			"problems": [{"source": "snyk_vuln", "id": "SNYK-EXAMPLE-1", "severity": "medium"}],
			"locations": [{"type": "package", "package": {"name": "example", "version": "1.2"}}]
		}}]}
	]`)
	requireTOONEqual(t, false, `sca[1]{fixable,id,pkg,severity}:
  no,SNYK-EXAMPLE-1,"example@1.2,1.10",high`, output)
}

func TestTOONMapping_SecretsFallbacks(t *testing.T) {
	t.Parallel()

	output := renderFindings(t, false, `[{"findings": [
		{"attributes": {"finding_type":"secrets", "title":"fallback", "rating":{"severity":"HIGH"},
			"problems":[{"source":"snyk_secrets_rule","id":"rule-1"},{"id":"rule-2"}],
			"locations":[{"type":"source","file_path":"first.txt","from_line":7,"to_line":10},
				{"type":"source","file_path":"second.txt","from_line":12}]}},
		{"attributes": {"finding_type":"secrets", "title":"fallback"}},
		{"attributes": {"finding_type":"secrets", "locations":[{"type":"source","from_line":"invalid"}]}},
		{}
	]}]`)
	requireTOONEqual(t, false, `secrets[3]{file,line,rule,severity}:
  first.txt,7,rule-1,high
  unknown,0,fallback,low
  unknown,0,secret,low`, output)
}

func TestTOONMapping_StableVersions(t *testing.T) {
	var findings []string
	for _, version := range []string{"1.0", "01.0", "1.0"} {
		findings = append(findings, fmt.Sprintf(`{"attributes":{"finding_type":"sca",
			"problems":[{"source":"snyk_vuln","id":"same","package_name":"example","package_version":%q}]}}`, version))
	}
	output := renderFindings(t, false, `[{"findings":[`+strings.Join(findings, ",")+`]}]`)
	requireTOONEqual(t, false, `sca[1]{fixable,id,pkg,severity}:
  no,same,"example@1.0,01.0",""`, output)
}

func TestTOONMapping_SCAFirstOccurrence(t *testing.T) {
	t.Parallel()
	var findings []string
	for i, id := range []string{"second", "first", "second", "", ""} {
		findings = append(findings, fmt.Sprintf(`{"attributes":{"finding_type":"sca","title":"Title %d",
			"problems":[{"source":"snyk_vuln","id":%q,"severity":"severity-%d","cvss_base_score":%d,
			"package_name":"package-%d","package_version":"%d"}]},
			"relationships":{"fix":{"data":{"attributes":{"action":{"format":"upgrade_package_advice",
			"upgrade_paths":[{"dependency_path":[{}, {"name":"target","version":"%d"}]}]}}}}}}`, i, id, i, i, i, i, i+1))
	}
	output := renderFindings(t, true, `[{"findings":[`+strings.Join(findings, ",")+`]}]`)
	requireTOONEqual(t, true, `sca[3]{cvss,fixable,id,pkg,severity,title,upgrade}:
  "0.0",yes,second,"package-0@0,2",severity-0,Title 0,target@1
  "1.0",yes,first,package-1@1,severity-1,Title 1,target@2
  "3.0",yes,"","package-3@3,4",severity-3,Title 3,target@4`, output)
}

func TestTOONMapping_EmptyScanners(t *testing.T) {
	t.Parallel()

	output := renderFindings(t, false, `[
		{"testConfiguration":{"scan_config":{"sca":{}}}},
		{"testConfiguration":{"scan_config":{"secrets":{}}},"findings":[]},
		{"testConfiguration":{"scan_config":{"sca":{},"secrets":{}}}}
	]`)
	requireTOONEqual(t, false, "sca: []\nsecrets: []", output)
}

func TestTOONMapping_SCAFixability(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, action, expected string
	}{
		{"upgrade", `{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{"name":"root","version":"1"},{"name":"example","version":"2"}]}]}`, "yes"},
		{"root only", `{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{"name":"root","version":"1"}],"is_drop":true}]}`, "no"},
		{"empty target", `{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{},{}]}]}`, "yes"},
		{"pin", `{"format":"pin_package_advice","package_name":"example","pin_version":"2"}`, "no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := renderFindings(t, false, fmt.Sprintf(`[{"findings":[
				{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"same","is_fixable":true}]}},
				{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln","id":"same"}]},
				 "relationships":{"fix":{"data":{"attributes":{"action":%s}}}}}
			]}]`, tc.action))
			requireTOONEqual(t, false, fmt.Sprintf(`sca[1]{fixable,id,pkg,severity}:
  %s,same,@,""`, tc.expected), output)
		})
	}
}

func TestTOONMapping_SCASources(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, attributes, expected string
	}{
		{
			"prefer first vulnerability over license and other identifiers",
			`"problems":[{"source":"snyk_license","id":"license"},{"source":"cve","id":"CVE-EXAMPLE"},
				{"source":"snyk_vuln","id":"first","severity":"high","package_name":"fallback","package_version":"3"},
				{"source":"snyk_vuln","id":"second","severity":"low"}],
			 "locations":[{"type":"source","file_path":"manifest"},{"type":"package","package":{"name":"installed","version":"2"}}]`,
			`no,first,installed@2,high`,
		},
		{
			"license package fallback",
			`"problems":[{"source":"snyk_license","id":"license","severity":"medium","package_name":"example","package_version":"3"}]`,
			`no,license,example@3,medium`,
		},
		{
			"null fields retain empty defaults",
			`"problems":[{"source":"snyk_vuln","id":null,"severity":null,"package_name":null,"package_version":null}]`,
			`no,"",@,""`,
		},
		{
			"empty ID and severity do not use finding fallbacks",
			`"key":"finding-key","rating":{"severity":"high"},"problems":[{"source":"snyk_vuln","package_name":"example","package_version":"3"}],
			 "locations":[{"type":"package","package":{"name":"installed"}}]`,
			`no,"",installed@3,""`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output := renderFindings(t, false, fmt.Sprintf(
				`[{"findings":[{"attributes":{"finding_type":"sca",%s}}]}]`, tc.attributes))
			requireTOONEqual(t, false, "sca[1]{fixable,id,pkg,severity}:\n  "+tc.expected, output)
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
			`[{"findings":[{"attributes":{"finding_type":"sca",%s}}]}]`, attributes)))
		require.NoError(t, err)
		value, err := renderTOONResults(t, results, false)
		require.Error(t, err)
		require.Empty(t, value)
	}
}

func renderFindings(t *testing.T, full bool, input string) string {
	t.Helper()
	results, err := ufm.NewSerializableTestResultFromBytes([]byte(input))
	require.NoError(t, err)
	output, err := renderTOONResults(t, results, full)
	require.NoError(t, err)
	return output
}

func TestTOONMapping_FullSCADetails(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, title, cvss, expectedTitle, expectedCVSS string
	}{
		{"missing", "short", "", "short", "n/a"},
		{"null", "", `,"cvss_base_score":null`, "", "n/a"},
		{"zero at title limit", strings.Repeat("界", 80), `,"cvss_base_score":0`, strings.Repeat("界", 80), "0.0"},
		{"rounded and truncated", strings.Repeat("界", 82), `,"cvss_base_score":7.86`, strings.Repeat("界", 80) + "…(+2 chars)", "7.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := fmt.Sprintf(`[{"findings":[{"attributes":{"finding_type":"sca","title":%q,
				"problems":[{"source":"snyk_vuln","id":"example"%s}]}}]}]`, tc.title, tc.cvss)
			output := renderFindings(t, true, input)
			title, err := toon.FormatTabularField(tc.expectedTitle)
			require.NoError(t, err)
			cvss, err := toon.FormatTabularField(tc.expectedCVSS)
			require.NoError(t, err)
			requireTOONEqual(t, true, fmt.Sprintf(`sca[1]{cvss,fixable,id,pkg,severity,title,upgrade}:
  %s,no,example,@,"",%s,none`, cvss, title), output)
		})
	}
}

func TestTOONMapping_FullSCAUpgrades(t *testing.T) {
	t.Parallel()
	output := renderFindings(t, true, `[{"findings":[
		{"attributes":{"finding_type":"sca","title":"without advice","problems":[{"source":"snyk_vuln","id":"same"}]}},
		{"attributes":{"finding_type":"sca","title":"empty target","problems":[{"source":"snyk_vuln","id":"same"}]},
		 "relationships":{"fix":{"data":{"attributes":{"action":{"format":"upgrade_package_advice","upgrade_paths":[{"dependency_path":[{},{}]}]}}}}}},
		{"attributes":{"finding_type":"sca","title":"upgrade","problems":[{"source":"snyk_vuln","id":"same","cvss_base_score":5}]},
		 "relationships":{"fix":{"data":{"attributes":{"action":{"format":"upgrade_package_advice","upgrade_paths":[
			{"dependency_path":[{"name":"root","version":"1"}]},
			{"dependency_path":[{"name":"root","version":"1"},{},{"name":"example","version":"2"},{"name":"other","version":"3"}]}]}}}}}}
	]}]`)
	requireTOONEqual(t, true, `sca[1]{cvss,fixable,id,pkg,severity,title,upgrade}:
  n/a,yes,same,@,"",without advice,none`, output)
}

func TestTOONMapping_CVSSValidationOnlyInFullOutput(t *testing.T) {
	t.Parallel()
	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[{"findings":[
		{"attributes":{"finding_type":"sca","problems":[{"source":"snyk_vuln"}]}},
		{"attributes":{
		"finding_type":"sca","problems":[{"source":"snyk_vuln","cvss_base_score":"invalid"}]
	}}]}]`))
	require.NoError(t, err)
	_, err = renderTOONResults(t, results, false)
	require.NoError(t, err)
	value, err := renderTOONResults(t, results, true)
	require.ErrorContains(t, err, "cvss_base_score")
	require.Empty(t, value)
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
				envelope, err := renderTOONResults(t, results, false)
				require.ErrorContains(t, err, "scan is "+state)
				require.Empty(t, envelope)
			})
		}
	}
}

func renderTOONResults(t *testing.T, results []testapi.TestResult, full bool) (string, error) {
	t.Helper()
	config := configuration.NewWithOpts()
	mode := "compact"
	if full {
		mode = "full"
	}
	config.Set("toon", mode)
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output)
	err := presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	return output.String(), err
}

func requireTOONEqual(t *testing.T, full bool, rows, output string) {
	t.Helper()
	header := "feedback: \"\"\n"
	if !full {
		header += "hint: add --toon=full for all fields\n"
	}
	header += "org: unknown\nproject: unknown\n"
	require.Equal(t, header+rows, output)
}
