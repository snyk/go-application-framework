package presenters_test

import (
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/internal/presenters"
	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sarifToLocalFinding(t *testing.T, filename string) (localFinding local_models.LocalFinding, err error) {
	t.Helper()
	jsonFile, err := os.Open("./" + filename)
	if err != nil {
		t.Errorf("Failed to load json")
	}

	defer func(jsonFile *os.File) {
		jsonErr := jsonFile.Close()
		assert.NoError(t, jsonErr)
	}(jsonFile)
	sarifBytes, err := io.ReadAll(jsonFile)
	assert.NoError(t, err)

	// Read sarif file again for summary
	var sarifDoc sarif.SarifDocument

	err = json.Unmarshal(sarifBytes, &sarifDoc)
	assert.NoError(t, err)

	summaryData := sarif_utils.CreateCodeSummary(&sarifDoc)
	summaryBytes, err := json.Marshal(summaryData)
	assert.NoError(t, err)

	return localworkflows.TransformToLocalFindingModel(sarifBytes, summaryBytes)
}

func TestPresenterLocalFinding_NoIssues(t *testing.T) {
	fd, err := os.Open("testdata/local-findings-empty.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scannedPath := "/path/to/project"
	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(localFindingDoc,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath(scannedPath))

	result, err := p.Render()

	require.NoError(t, err)
	assert.Contains(t, result, "Testing "+scannedPath)
	assert.NotContains(t, result, "Ignored issues")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_LowIssues(t *testing.T) {
	// Convert our sarif into localfindings
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.NoError(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.NoError(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssues(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)

	require.Contains(t, result, "[ 0 HIGH  0 MEDIUM  0 LOW ]")
	require.Contains(t, result, "[ 4 HIGH  5 MEDIUM  0 LOW ]")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssuesWithColor(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "You are currently viewing results with --severity-threshold=high applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssuesWithColorLight(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(false)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "You are currently viewing results with --severity-threshold=high applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_SeverityThresholdHighIssues(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsSeverityLevel("high"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.Contains(t, result, "[ 0 HIGH ]")
	require.Contains(t, result, "[ 4 HIGH ]")

	require.Contains(t, result, "You are currently viewing results with --severity-threshold applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_DefaultHideIgnored(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsIgnoredIssues(false),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "src/main.ts, line 58")
	require.NotContains(t, result, "Ignored Issues")
}

func TestPresenterLocalFinding_IncludeIgnored(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsIgnoredIssues(true),
	)

	result, err := p.Render()

	require.Nil(t, err)

	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, "[ IGNORED ] [MEDIUM]")
	require.Contains(t, result, "src/main.ts, line 58")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.NotContains(t, result, "Empty ignore issues state")
	require.NotContains(t, result, "To view ignored and open issues, use the --include-ignores option.pre")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_IncludeIgnoredEmpty(t *testing.T) {
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.LocalFindingsTestResults(
		input,
		presenters.WithLocalFindingsOrg("test-org"),
		presenters.WithLocalFindingsTestPath("/path/to/project"),
		presenters.WithLocalFindingsIgnoredIssues(true),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")

	snaps.MatchSnapshot(t, result)
}
