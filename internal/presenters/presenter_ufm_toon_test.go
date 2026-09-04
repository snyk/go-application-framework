package presenters_test

import (
	"bytes"
	"os"
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

func TestRenderTemplate_TOON_goldens(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		fixture    string
		golden     string
		testResult func(t *testing.T) []testapi.TestResult
	}{
		{
			name:    "SCA representative",
			fixture: "testdata/ufm/sca.toon.testresult.json",
			golden:  "testdata/ufm/toon/sca.concise.toon",
		},
		{
			name:    "Secrets representative",
			fixture: "testdata/ufm/secrets.toon.testresult.json",
			golden:  "testdata/ufm/toon/secrets.concise.toon",
		},
		{
			name:   "SCA empty",
			golden: "testdata/ufm/toon/sca.concise-empty.toon",
			testResult: emptySCATestResults,
		},
		{
			name:   "Secrets empty",
			golden: "testdata/ufm/toon/secrets.concise-empty.toon",
			testResult: emptySecretsTestResults,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var results []testapi.TestResult
			if tc.testResult != nil {
				results = tc.testResult(t)
			} else {
				results = loadUFMTestResults(t, tc.fixture)
			}

			expected, err := os.ReadFile(tc.golden)
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

func emptySCATestResults(t *testing.T) []testapi.TestResult {
	t.Helper()
	return []testapi.TestResult{emptyTypedTestResult(t, "testdata/ufm/sca.toon.testresult.json")}
}

func emptySecretsTestResults(t *testing.T) []testapi.TestResult {
	t.Helper()
	return []testapi.TestResult{emptyTypedTestResult(t, "testdata/ufm/secrets.toon.testresult.json")}
}

func loadUFMTestResults(t *testing.T, path string) []testapi.TestResult {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	results, err := ufm.NewSerializableTestResultFromBytes(raw)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	return results
}

func emptyTypedTestResult(t *testing.T, configFixturePath string) testapi.TestResult {
	t.Helper()
	results := loadUFMTestResults(t, configFixturePath)

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockTestResult(ctrl)
	mock.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
	mock.EXPECT().GetTestConfiguration().Return(results[0].GetTestConfiguration()).AnyTimes()
	return mock
}
