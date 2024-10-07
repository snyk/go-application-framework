package presenters

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"text/template"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on windows device [CLI-514]")
	}
}

func TestPresenterLocalFinding_NoIssues(t *testing.T) {
	skipWindows(t)
	fd, err := os.Open("testdata/local-findings-empty.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scanned_path := "path/to/project"
	p := LocalFindingPresenter(
		localFindingDoc,
		scanned_path,
	)

	result, err := p.Render()

	require.NoError(t, err)
	assert.Contains(t, result, "Testing "+scanned_path)
	assert.NotContains(t, result, "Ignored issues")
}

var test_finding = local_models.FindingResource{
	Attributes: local_models.FindingAttributes{
		Message: struct {
			Arguments []string `json:"arguments"`
			Header    string   `json:"header"`
			Markdown  string   `json:"markdown"`
			Text      string   `json:"text"`
		}{
			Arguments: []string{"test"},
			Header:    "Cleartext Transmission of Sensitive Information",
			Markdown:  "test",
			Text:      "http.createServer uses HTTP which is an insecure protocol and should not be used in code due to cleartext transmission of information. Data in cleartext in a communication channel can be sniffed by unauthorized actors. Consider using the https module instead.",
		},
		Component: local_models.Component{
			Name:     "test",
			ScanType: "sast",
		},
		Fingerprint: local_models.Fingerprint{},
		Rating: &local_models.FindingRating{
			Severity: struct {
				OriginalValue *local_models.FindingRatingSeverityOriginalValue `json:"original_value,omitempty"`
				Reason        *local_models.FindingRatingSeverityReason        `json:"reason,omitempty"`
				Value         local_models.FindingRatingSeverityValue          `json:"value"`
			}{
				OriginalValue: nil,
				Reason:        nil,
				Value:         "low",
			},
		},
		Locations: &[]local_models.FindingLocation{
			{
				DependencyPath: &[]local_models.ScaPackage{
					{
						PackageName:    "test",
						PackageVersion: "test",
					},
				},
				SourceLocations: &local_models.FindingSourceLocation{
					Filepath:            "node_modules/qs/support/expresso/test/http.test.js",
					OriginalEndColumn:   1,
					OriginalEndLine:     1,
					OriginalStartColumn: 1,
					OriginalStartLine:   1,
				},
			},
		},
	},
}

func TestFindingComponent(t *testing.T) {
	skipWindows(t)
	test_template, err := template.New("test_template").Parse("")
	require.NoError(t, err)
	AddTemplateFuncs(test_template)
	err = LoadTemplates([]string{
		TemplatePaths.FindingComponentTemplate}, test_template)
	require.NoError(t, err)

	output := new(bytes.Buffer)

	test_template.Lookup("finding").Execute(output, test_finding)

	require.Contains(t, output.String(), test_finding.Attributes.Message.Header)
	require.Contains(t, output.String(), test_finding.Attributes.Message.Text)
	require.Contains(t, output.String(), test_finding.Attributes.Rating.Severity.Value)
	snaps.MatchSnapshot(t, output.String())
}

func TestBoxStyle(t *testing.T) {
	skipWindows(t)
	test_template, err := template.New("test_template").Parse("")
	require.NoError(t, err)
	AddTemplateFuncs(test_template)
	err = LoadTemplates([]string{
		TemplatePaths.FindingComponentTemplate}, test_template)
	require.NoError(t, err)

	output := new(bytes.Buffer)

	test_template, err = test_template.Parse("{{ (renderToString \"finding\" .) | box }}")
	require.NoError(t, err)
	test_template.Execute(output, test_finding)

	snaps.MatchSnapshot(t, output.String())
}

func TestPresenterLocalFinding_with_Issues(t *testing.T) {
	skipWindows(t)
	fd, err := os.Open("testdata/local-findings-juice-shop.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scanned_path := "path/to/project"
	p := LocalFindingPresenter(
		localFindingDoc,
		scanned_path,
	)

	result, err := p.Render()

	require.NoError(t, err)
	assert.Contains(t, result, "Total issues:   18")
	assert.Contains(t, result, "Static code analysis")
	assert.Contains(t, result, "╭")
	snaps.MatchSnapshot(t, result)
}
