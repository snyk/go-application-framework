package presenters_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui/uitypes"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func TestNewUfmRenderer_registersTOON(t *testing.T) {
	t.Parallel()

	presenter := presenters.NewUfmRenderer(nil, configuration.NewWithOpts(), &bytes.Buffer{})
	err := presenter.RegisterMimeType(presenters.ApplicationTOONMimeType, func() (*template.Template, template.FuncMap, error) {
		tmpl, parseErr := template.New("dup").Parse("")
		return tmpl, nil, parseErr
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestRenderTemplate_TOON_contractGoldens(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		inputs []string
	}{
		{"sca", []string{"sca"}},
		{"secrets", []string{"secrets"}},
		{"empty_sca", []string{"empty_sca"}},
		{"empty_secrets", []string{"empty_secrets"}},
		{"mixed_scanners", []string{"secrets", "empty_sca", "sca", "empty_secrets"}},
		{"no_results", []string{"no_results"}},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/compact", tc.name), func(t *testing.T) {
			t.Parallel()
			fixtureDir := filepath.Join("testdata", "ufm", "toon")
			var results []testapi.TestResult
			for _, name := range tc.inputs {
				results = append(results, loadContractTestResults(t, filepath.Join(fixtureDir, name+".json"))...)
			}
			expected, err := os.ReadFile(filepath.Join(fixtureDir, tc.name+".toon"))
			require.NoError(t, err)
			expected = bytes.TrimSuffix(expected, []byte("\n"))

			writer := &bytes.Buffer{}
			presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), writer)
			require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Equal(t, string(expected), writer.String())
		})
	}
}

func TestRenderTemplate_TOON_fullUsesSARIFReport(t *testing.T) {
	t.Parallel()

	for _, mode := range []any{"full", true} {
		t.Run(fmt.Sprintf("mode=%v", mode), func(t *testing.T) {
			t.Parallel()
			results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", "sca.json"))
			config := configuration.NewWithOpts()
			config.Set("toon", mode)
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, config, &output)

			require.NoError(t, presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Contains(t, output.String(), "runs[1]")
			assert.NotContains(t, output.String(), "hint: add --toon=full")
		})
	}

	t.Run("false stays compact", func(t *testing.T) {
		results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", "sca.json"))
		config := configuration.NewWithOpts()
		config.Set("toon", false)
		var output bytes.Buffer
		presenter := presenters.NewUfmRenderer(results, config, &output)

		require.NoError(t, presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
		assert.Contains(t, output.String(), "sca[")
		assert.NotContains(t, output.String(), "runs[")
	})
}

func TestRenderTemplate_TOON_fullUsesProvidedTemplate(t *testing.T) {
	t.Parallel()

	templatePath := filepath.Join(t.TempDir(), "toon.tmpl")
	require.NoError(t, os.WriteFile(templatePath, []byte(`{{- define "toonDocument" -}}custom{{- end -}}`), 0600))

	results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", "sca.json"))
	config := configuration.NewWithOpts()
	config.Set("toon", "full")
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output)

	require.NoError(t, presenter.RenderTemplateWithContext(t.Context(), []string{templatePath}, presenters.ApplicationTOONMimeType))
	assert.Equal(t, "custom", output.String())
}

func TestRenderTemplate_TOON_fullRejectsUnfinishedScan(t *testing.T) {
	t.Parallel()

	for _, state := range []string{"pending", "started"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			results, err := ufm.NewSerializableTestResultFromBytes([]byte(fmt.Sprintf(
				`[{"executionState":%q,"findingsComplete":true,"testConfiguration":{"scan_config":{"sca":{}}}}]`, state)))
			require.NoError(t, err)
			config := configuration.NewWithOpts()
			config.Set("toon", true)
			output := bytes.NewBufferString("original")
			presenter := presenters.NewUfmRenderer(results, config, output)

			err = presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
			require.ErrorContains(t, err, "scan is "+state)
			assert.Equal(t, "original", output.String())
		})
	}
}

func TestRenderTemplate_TOON_fullPreservesDiagnostics(t *testing.T) {
	t.Parallel()

	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[
		{"executionState":"finished","testConfiguration":{"scan_config":{"secrets":{}}},
		 "errors":[{"detail":"Some files failed"}],"warnings":[{"detail":"Some files skipped"}],
		 "findings":[{"id":"00000000-0000-4000-8000-000000000001","attributes":{"finding_type":"secrets","title":"Secret rule","rating":{"severity":"medium"},
		 "problems":[{"id":"SECRET-RULE","source":"secret"}],"locations":[{"file_path":"config.env","from_line":3,"type":"source"}]}}]}
	]`))
	require.NoError(t, err)
	config := configuration.NewWithOpts()
	config.Set("toon", "full")
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output)

	require.NoError(t, presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
	assert.Contains(t, output.String(), "runs[1]")
	assert.Contains(t, output.String(), "secrets_error: Some files failed")
	assert.Contains(t, output.String(), "secrets_hint: Some files skipped")
	assert.NotContains(t, output.String(), "secrets: []")
	assert.NotContains(t, output.String(), "findings: []")
}

func TestRenderTemplate_TOON_fullGolden(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Join("testdata", "ufm", "toon")
	results := loadContractTestResults(t, filepath.Join(fixtureDir, "got_sarif_full.json"))
	config := configuration.NewWithOpts()
	config.Set("toon", "full")
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output,
		presenters.UfmWithRuntimeInfo(runtimeinfo.New(runtimeinfo.WithName("snyk"), runtimeinfo.WithVersion("1.1301.0"))),
	)

	require.NoError(t, presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
	expected, err := os.ReadFile(filepath.Join(fixtureDir, "got_sarif_full.toon"))
	require.NoError(t, err)
	assert.Equal(t, string(bytes.TrimSuffix(expected, []byte("\n"))), output.String())
}

func TestRenderTemplate_TOON_fullPreservesRunsRulesAndResults(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Join("testdata", "ufm", "toon")
	results := loadContractTestResults(t, filepath.Join(fixtureDir, "multi_sarif_full.json"))
	config := configuration.NewWithOpts()
	config.Set("toon", "full")
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output)

	require.NoError(t, presenter.RenderTemplateWithContext(t.Context(), presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
	expected, err := os.ReadFile(filepath.Join(fixtureDir, "multi_sarif_full.toon"))
	require.NoError(t, err)
	assert.Equal(t, string(bytes.TrimSuffix(expected, []byte("\n"))), output.String())
	assert.Contains(t, output.String(), "runs[2]:")
	assert.Contains(t, output.String(), "results[2]:")
	assert.Contains(t, output.String(), "rules[2]:")
	assert.Contains(t, output.String(), "ruleId: SECRET-RULE-A")
	assert.Contains(t, output.String(), "ruleId: SECRET-RULE-B")
}

func TestRenderTemplate_TOON_genericFindings(t *testing.T) {
	t.Parallel()
	results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", "nested.json"))
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
	err := presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.NoError(t, err)
	assert.Contains(t, output.String(), "findings[1]{finding_type,id,severity,title}:\n  sast,finding-4,high,Example finding")
	assert.NotContains(t, output.String(), "results[")
}

func TestRenderTemplate_TOON_genericDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        []string
	}{
		{
			"unidentified failure",
			`[{"executionState":"errored"}]`,
			[]string{"errors: Scan failed.", "findings: []", "hint: Retry the scan."},
		},
		{
			"empty future scan with warning",
			`[{"executionState":"finished","testConfiguration":{"scan_config":{"sast":{}}},"warnings":[{"detail":"Some files skipped"}]}]`,
			[]string{"findings: []", "warnings: Some files skipped"},
		},
		{
			"future findings with partial diagnostics",
			`[{"errors":[{"detail":"Some files failed"}],"warnings":[{"title":"Partial scan"}],"findings":[
				{"attributes":{"finding_type":"future","title":"Future finding","rating":{"severity":"high"},"problems":[{"source":42}]}},
				{"attributes":{"finding_type":"future"}}]}]`,
			[]string{"errors: Some files failed", "warnings: Partial scan", "hint: Retry the scan.",
				"findings[1]{finding_type,id,severity,title}:\n  future,\"\",high,Future finding"},
		},
		{
			"license findings mark the sca scanner",
			`[{"errors":[{"detail":"License failure"}],"findings":[
				{"attributes":{"finding_type":"sca","rating":{"severity":"low"},"problems":[{"source":"snyk_license","id":"snyk:lic:npm:x:MIT"}]}}]}]`,
			[]string{"sca_error: License failure", "sca[1]"},
		},
		{
			"scanner and generic diagnostics stay separate",
			`[{"testConfiguration":{"scan_config":{"sca":{}}},"errors":[{"detail":"SCA failure"}]},
				{"errors":[{"detail":"Other failure"}]}]`,
			[]string{"errors: Other failure", "sca_error: SCA failure", "sca_hint: Retry the scan.", "hint: Retry the scan."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, err := ufm.NewSerializableTestResultFromBytes([]byte(tc.input))
			require.NoError(t, err)
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
			ctx := context.WithValue(t.Context(), uitypes.ErrorTipKey, "Retry the scan.")
			require.NoError(t, presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			for _, want := range tc.want {
				assert.Contains(t, output.String(), want)
			}
			assert.NotContains(t, output.String(), "results[")
			if strings.Contains(output.String(), "errors:") {
				assert.NotContains(t, output.String(), "add --toon=full")
			}
		})
	}
}

func TestRenderTemplate_TOON_controlCharacters(t *testing.T) {
	t.Parallel()

	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[{
		"findings": [{"type": "findings", "attributes": {
			"finding_type": "secrets", "title": "bad\u0001title", "rating": {"severity": "low"},
			"problems": [{"source": "new_product", "details": {"key\u0001\\n\n\"": "value"}}]
		}}]
	}]`))
	require.NoError(t, err)

	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
	err = presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.NoError(t, err)
	assert.Contains(t, output.String(), `unknown,0,"bad\u0001title",low`)
	assert.NotContains(t, output.String(), "key")
}

func loadContractTestResults(t *testing.T, envelopePath string) []testapi.TestResult {
	t.Helper()

	raw, err := os.ReadFile(envelopePath)
	require.NoError(t, err)

	var envelope struct {
		Results json.RawMessage `json:"results"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))

	results, err := ufm.NewSerializableTestResultFromBytes(envelope.Results)
	require.NoError(t, err)
	return results
}

func TestRenderTemplate_TOON_context(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, slug, org, directory, expectedOrg, expectedProject string
	}{
		{"slug first", "team", "org-id", filepath.Join("workspace", "project"), "team", "project"},
		{"org fallback", "", "org-id", "", "org-id", "unknown"},
		{"missing", "", "", "", "unknown", "unknown"},
		{"numeric slug", "1", "", "", `"1"`, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			config := configuration.NewWithOpts()
			config.Set(configuration.ORGANIZATION_SLUG, tc.slug)
			config.Set(configuration.ORGANIZATION, tc.org)
			config.Set(configuration.INPUT_DIRECTORY, tc.directory)
			results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", "empty_sca.json"))
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, config, &output)
			require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Contains(t, output.String(), "org: "+tc.expectedOrg)
			assert.Contains(t, output.String(), "project: "+tc.expectedProject)
			assert.NotContains(t, output.String(), "interaction_id:")
		})
	}
}

func TestRenderTemplate_TOON_scanDiagnostics(t *testing.T) {
	t.Parallel()
	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[
		{"findingsComplete":true,"executionState":"errored","testConfiguration":{"scan_config":{"sca":{}}},
		 "errors":[{"detail":"Dependency scan failed","status":"500","meta":{"unused":"excluded"}}],
		 "warnings":[{"title":"Some manifests were skipped"},{"code":"SCAN-WARNING"}]},
		{"findingsComplete":true,"errors":[{"detail":"Some files could not be scanned"}],
		 "warnings":[{"detail":"Results are incomplete"}],
		 "findings":[{"attributes":{"finding_type":"secrets","title":"rule","rating":{"severity":"low"}}}]}
	]`))
	require.NoError(t, err)
	config := configuration.NewWithOpts()
	ctx := context.WithValue(t.Context(), uitypes.ErrorTipKey, "Retry the scan.")
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, config, &output)
	require.NoError(t, presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
	assert.Contains(t, output.String(), "sca_error: Dependency scan failed")
	assert.Contains(t, output.String(), "sca_hint: Retry the scan.")
	assert.Contains(t, output.String(), `sca_warning: "Some manifests were skipped\nSCAN-WARNING"`)
	assert.Contains(t, output.String(), "secrets_error: Some files could not be scanned")
	assert.Contains(t, output.String(), `secrets_hint: "Results are incomplete\nRetry the scan."`)
	assert.Contains(t, output.String(), "unknown,0,rule,low")
	assert.NotContains(t, output.String(), "add --toon=full")
	assert.NotContains(t, output.String(), "excluded")
}

func TestRenderTemplate_TOON_findingsError(t *testing.T) {
	t.Parallel()
	findings := []testapi.FindingData{{Attributes: &testapi.FindingAttributes{
		FindingType: testapi.FindingTypeSecrets, Title: "kept",
	}}}
	ctx := t.Context()
	mock := mocks.NewMockTestResult(gomock.NewController(t))
	mock.EXPECT().Findings(ctx).Return(findings, false, assert.AnError)
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer([]testapi.TestResult{mock}, configuration.NewWithOpts(), &output)
	err := presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.ErrorIs(t, err, assert.AnError)
	require.ErrorContains(t, err, "findings")
	assert.Empty(t, output.String())
}

func TestRenderTemplate_TOON_laterResultError(t *testing.T) {
	ctx := t.Context()
	ctrl := gomock.NewController(t)
	first := mocks.NewMockTestResult(ctrl)
	first.EXPECT().Findings(ctx).Return([]testapi.FindingData{{Attributes: &testapi.FindingAttributes{
		FindingType: testapi.FindingTypeSecrets, Title: "valid",
	}}}, true, nil).Times(1)
	first.EXPECT().GetTestConfiguration().Return(nil)
	first.EXPECT().GetErrors().Return(nil)
	first.EXPECT().GetWarnings().Return(nil)
	first.EXPECT().GetExecutionState().Return(testapi.TestExecutionStates(""))
	second := mocks.NewMockTestResult(ctrl)
	second.EXPECT().Findings(ctx).Return(nil, false, assert.AnError).Times(1)

	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer([]testapi.TestResult{first, second}, configuration.NewWithOpts(), &output)
	err := presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.ErrorIs(t, err, assert.AnError)
	require.ErrorContains(t, err, "failed to extract findings")
	assert.Empty(t, output.String())
}

func TestRenderTemplate_TOON_fullFindingsErrorUsesContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	result := mocks.NewMockTestResult(ctrl)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result.EXPECT().GetTestConfiguration().Return(nil)
	result.EXPECT().Findings(ctx).Return(nil, false, assert.AnError)

	config := configuration.NewWithOpts()
	config.Set("toon", "full")
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer([]testapi.TestResult{result}, config, &output)
	err := presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)

	require.ErrorContains(t, err, "failed to extract findings")
	assert.Empty(t, output.String())
}

func TestRenderTemplate_TOON_secretFindingTypes(t *testing.T) {
	for _, kind := range []string{"secret", "secrets"} {
		t.Run(kind, func(t *testing.T) {
			results, err := ufm.NewSerializableTestResultFromBytes([]byte(fmt.Sprintf(`[
				{"findings":[{"attributes":{"finding_type":%q,"title":"rule","rating":{"severity":"low"}}}]}
			]`, kind)))
			require.NoError(t, err)
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
			require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Contains(t, output.String(), "secrets[1]{file,line,rule,severity}:\n  unknown,0,rule,low")
		})
	}
}
