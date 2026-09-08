package presenters_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
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

	cases := []string{
		"sca",
		"secrets",
		"empty_sca",
		"empty_secrets",
		"mixed",
		"nested",
		"no_results",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fixtureDir := filepath.Join("testdata", "ufm", "toon")
			results := loadContractTestResults(t, filepath.Join(fixtureDir, name+".json"))
			expected, err := os.ReadFile(filepath.Join(fixtureDir, name+".toon"))
			require.NoError(t, err)
			expected = bytes.TrimSuffix(expected, []byte("\n"))

			writer := &bytes.Buffer{}
			presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), writer)
			require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))

			assert.Equal(t, string(expected), writer.String())
		})
	}
}

func TestRenderTemplate_TOON_findingsError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockTestResult(ctrl)
	mock.EXPECT().Findings(gomock.Any()).Return(nil, false, assert.AnError)

	writer := &bytes.Buffer{}
	presenter := presenters.NewUfmRenderer([]testapi.TestResult{mock}, configuration.NewWithOpts(), writer)
	err := presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "findings")
}

func TestRenderTemplate_TOON_genericFindings(t *testing.T) {
	t.Parallel()

	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[{
		"executionState": "finished",
		"findings": [{"type": "findings", "attributes": {
			"finding_type": "new_product",
			"problems": [{"source": "new_product", "details": {
				"arrays": [[], [[true, false], null]],
				"credits": ["Doe, Jane", "Smith"],
				"nestedCredits": [["Doe, Jane", "Smith"]],
				"rows": [{"a": [1, 2]}, {"a": [{"nested": {"value": true}}]}]
			}}]
		}}]
	}]`))
	require.NoError(t, err)

	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
	require.NoError(t, presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType))
	assert.Contains(t, output.String(), "finding_type: new_product")
	assert.Contains(t, output.String(), "source: new_product")
	assert.Contains(t, output.String(), `credits[2]: "Doe, Jane",Smith`)
	assert.Contains(t, output.String(), "nestedCredits[1]:\n                  - [2]: \"Doe, Jane\",Smith")
	assert.Contains(t, output.String(), "arrays[2]:\n                  - []\n                  - [2]:\n                    - [2]: true,false\n                    - null")
	assert.Contains(t, output.String(), "rows[2]:\n                  - a[2]: 1,2\n                  - a[1]{nested{value}}:\n                      true")
}

func TestRenderTemplate_TOON_formattingError(t *testing.T) {
	t.Parallel()

	results, err := ufm.NewSerializableTestResultFromBytes([]byte(`[{
		"findings": [{"type": "findings", "attributes": {"title": "bad\u0001title"}}]
	}]`))
	require.NoError(t, err)

	var output bytes.Buffer
	presenter := presenters.NewUfmRenderer(results, configuration.NewWithOpts(), &output)
	err = presenter.RenderTemplate(presenters.ApplicationTOONTemplatesUfm, presenters.ApplicationTOONMimeType)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported control character U+0001")
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
