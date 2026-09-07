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

			got := bytes.TrimSuffix(writer.Bytes(), []byte("\n"))
			assert.Equal(t, string(expected), string(got))
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
