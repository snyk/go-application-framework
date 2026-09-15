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
		name       string
		inputs     []string
		fullGolden string
	}{
		{"sca", []string{"sca"}, "sca_full"},
		{"secrets", []string{"secrets"}, ""},
		{"empty_sca", []string{"empty_sca"}, ""},
		{"empty_secrets", []string{"empty_secrets"}, ""},
		{"mixed_scanners", []string{"secrets", "empty_sca", "sca", "empty_secrets"}, "mixed_scanners_full"},
		{"no_results", []string{"no_results"}, ""},
	}

	for _, tc := range cases {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/full=%t", tc.name, full), func(t *testing.T) {
				t.Parallel()
				fixtureDir := filepath.Join("testdata", "ufm", "toon")
				var results []testapi.TestResult
				for _, name := range tc.inputs {
					results = append(results, loadContractTestResults(t, filepath.Join(fixtureDir, name+".json"))...)
				}
				golden := tc.name
				config := configuration.NewWithOpts()
				if full {
					config.Set(presenters.CONFIG_TOON_FULL, true)
					if tc.fullGolden != "" {
						golden = tc.fullGolden
					}
				}
				expected, err := os.ReadFile(filepath.Join(fixtureDir, golden+".toon"))
				require.NoError(t, err)
				expected = bytes.TrimSuffix(expected, []byte("\n"))
				if full {
					expected = bytes.Replace(expected, []byte("hint: add --full for all fields\n"), nil, 1)
				}

				writer := &bytes.Buffer{}
				presenter := presenters.NewUfmRenderer(results, config, writer)
				require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
				assert.Equal(t, string(expected), writer.String())
			})
		}
	}
}

func TestRenderTemplate_TOON_genericFindings(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nested", "mixed"} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/full=%t", name, full), func(t *testing.T) {
				t.Parallel()
				results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", name+".json"))
				var output bytes.Buffer
				config := configuration.NewWithOpts()
				config.Set(presenters.CONFIG_TOON_FULL, full)
				presenter := presenters.NewUfmRenderer(results, config, &output)
				err := presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
				require.NoError(t, err)
				assert.Contains(t, output.String(), "findings[1]{finding_type,id,severity,title}:\n  sast,00000000-0000-4000-8000-000000000004,high,Example finding")
				assert.NotContains(t, output.String(), "results[")
				if name == "mixed" {
					assert.Contains(t, output.String(), "sca[1]")
					assert.Contains(t, output.String(), "secrets[1]")
				}
			})
		}
	}
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
				"findings[2]{finding_type,id,severity,title}:\n  future,\"\",high,Future finding\n  future,\"\",\"\",\"\""},
		},
		{
			"scanner and generic diagnostics stay separate",
			`[{"testConfiguration":{"scan_config":{"sca":{}}},"errors":[{"detail":"SCA failure"}]},
				{"errors":[{"detail":"Other failure"}]}]`,
			[]string{"errors: Other failure", "sca_error: SCA failure", "sca_hint: Retry the scan.", "hint: Retry the scan."},
		},
	} {
		for _, full := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/full=%t", tc.name, full), func(t *testing.T) {
				results, err := ufm.NewSerializableTestResultFromBytes([]byte(tc.input))
				require.NoError(t, err)
				config := configuration.NewWithOpts()
				config.Set(presenters.CONFIG_TOON_FULL, full)
				var output bytes.Buffer
				presenter := presenters.NewUfmRenderer(results, config, &output)
				ctx := context.WithValue(t.Context(), uitypes.ErrorTipKey, "Retry the scan.")
				require.NoError(t, presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
				for _, want := range tc.want {
					assert.Contains(t, output.String(), want)
				}
				assert.NotContains(t, output.String(), "results[")
				if full || strings.Contains(output.String(), "errors:") {
					assert.NotContains(t, output.String(), "add --full")
				}
			})
		}
	}
}

func TestRenderTemplate_TOON_controlCharacters(t *testing.T) {
	t.Parallel()

	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[{
		"findings": [{"type": "findings", "attributes": {
			"finding_type": "secrets", "title": "bad\u0001title",
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
			config.Set(configuration.WORKING_DIRECTORY, tc.directory)
			results := loadContractTestResults(t, filepath.Join("testdata", "ufm", "toon", "empty_sca.json"))
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, config, &output)
			require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Contains(t, output.String(), "org: "+tc.expectedOrg)
			assert.Contains(t, output.String(), "project: "+tc.expectedProject)
			assert.Contains(t, output.String(), `feedback: ""`)
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
		 "findings":[{"attributes":{"finding_type":"secrets","title":"rule"}}]}
	]`))
	require.NoError(t, err)
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint(full), func(t *testing.T) {
			t.Parallel()
			config := configuration.NewWithOpts()
			config.Set(presenters.CONFIG_TOON_FULL, full)
			config.Set(presenters.CONFIG_TOON_FEEDBACK, "Share feedback:\nUse the host feedback command.")
			ctx := context.WithValue(t.Context(), uitypes.ErrorTipKey, "Retry the scan.")
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, config, &output)
			require.NoError(t, presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Contains(t, output.String(), `feedback: "Share feedback:\nUse the host feedback command."`)
			assert.Contains(t, output.String(), "sca_error: Dependency scan failed")
			assert.Contains(t, output.String(), "sca_hint: Retry the scan.")
			assert.Contains(t, output.String(), `sca_warning: "Some manifests were skipped\nSCAN-WARNING"`)
			assert.Contains(t, output.String(), "secrets_error: Some files could not be scanned")
			assert.Contains(t, output.String(), `secrets_hint: "Results are incomplete\nRetry the scan."`)
			assert.Contains(t, output.String(), "unknown,0,rule,low")
			assert.NotContains(t, output.String(), "add --full")
			assert.NotContains(t, output.String(), "excluded")
		})
	}
}

func TestRenderTemplate_TOON_findingsError(t *testing.T) {
	t.Parallel()
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			t.Parallel()
			var findings []testapi.FindingData
			if partial {
				findings = []testapi.FindingData{{Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSecrets, Title: "kept",
				}}}
			}
			ctx := t.Context()
			mock := mocks.NewMockTestResult(gomock.NewController(t))
			mock.EXPECT().Findings(ctx).Return(findings, false, assert.AnError)
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer([]testapi.TestResult{mock}, configuration.NewWithOpts(), &output)
			err := presenter.RenderTemplateWithContext(ctx, presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
			require.ErrorIs(t, err, assert.AnError)
			require.ErrorContains(t, err, "findings")
			assert.Empty(t, output.String())
		})
	}
}

func TestRenderTemplate_TOON_laterResultError(t *testing.T) {
	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[
		{"findings":[{"attributes":{"finding_type":"secrets","title":"valid"}}]},
		{"findings":[{"attributes":{"finding_type":"sca","problems":[{"source":"unsupported"}]}}]}
	]`))
	require.NoError(t, err)
	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
	require.Error(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
	assert.Empty(t, output.String())
}

func TestRenderTemplate_TOON_secretFindingTypes(t *testing.T) {
	for _, kind := range []string{"secret", "secrets"} {
		t.Run(kind, func(t *testing.T) {
			results, err := ufm.NewSerializableTestResultFromBytes([]byte(fmt.Sprintf(`[
				{"findings":[{"attributes":{"finding_type":%q,"title":"rule"}}]}
			]`, kind)))
			require.NoError(t, err)
			var output bytes.Buffer
			presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
			require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
			assert.Contains(t, output.String(), "secrets[1]{file,line,rule,severity}:\n  unknown,0,rule,low")
		})
	}
}
