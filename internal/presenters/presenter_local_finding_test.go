package presenters

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"

	"cuelang.org/go/cue/cuecontext"
	cuejson "cuelang.org/go/pkg/encoding/json"
	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/code-client-go/sarif"
	cueutil "github.com/snyk/go-application-framework/internal/cueutils"
	sarif_utils "github.com/snyk/go-application-framework/internal/utils/sarif"
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
	byteValue, err := io.ReadAll(jsonFile)
	assert.NoError(t, err)

	// Read sarif file again for sarif
	var sarifDoc sarif.SarifDocument

	err = json.Unmarshal(byteValue, &sarifDoc)
	assert.NoError(t, err)
	if err != nil {
		return local_models.LocalFinding{}, err
	}

	input, errUnJson := cuejson.Unmarshal(byteValue)
	assert.NoError(t, errUnJson)

	if errUnJson != nil {
		return localFinding, fmt.Errorf("failed to unmarshal input: %w", err)
	}

	ctx := cuecontext.New()
	sarif2apiTransformer, transformerError := cueutil.NewTransformer(ctx, cueutil.ToTestApiFromSarif)
	if transformerError != nil {
		return localFinding, transformerError
	}

	api2cliTransformer, transformerError := cueutil.NewTransformer(ctx, cueutil.ToCliFromTestApi)
	if transformerError != nil {
		return localFinding, transformerError
	}

	apiOutput, applyError := sarif2apiTransformer.Apply(input)
	if applyError != nil {
		return localFinding, applyError
	}

	cliOutput, applyError := api2cliTransformer.ApplyValue(apiOutput)
	if applyError != nil {
		return localFinding, applyError
	}

	// Gate with validation before encoding?
	encodeErr := cliOutput.Decode(&localFinding)

	if encodeErr != nil {
		return localFinding, fmt.Errorf("failed to convert to type: %w", encodeErr)
	}

	summaryData := sarif_utils.CreateCodeSummary(&sarifDoc)

	localFinding.Summary = *summaryData

	return localFinding, nil
}

func TestPresenterLocalFinding_NoIssues(t *testing.T) {
	skipWindows(t)
	fd, err := os.Open("testdata/local-findings-empty.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scannedPath := "path/to/project"
	p := LocalFindingsTestResults(localFindingDoc, WithLocalFindingsTestPath(scannedPath))

	result, err := p.Render()

	require.NoError(t, err)
	assert.Contains(t, result, "Testing "+scannedPath)
	assert.NotContains(t, result, "Ignored issues")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_LowIssues(t *testing.T) {
	skipWindows(t)
	// Convert our sarif into localfindings
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssues(t *testing.T) {
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)

	require.Contains(t, result, "[ 0 HIGH  0 MEDIUM  0 LOW ]")
	require.Contains(t, result, "[ 4 HIGH  5 MEDIUM  0 LOW ]")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssuesWithColor(t *testing.T) {
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "You are currently viewing results with --severity-threshold=high applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_MediumHighIssuesWithColorLight(t *testing.T) {
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(false)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "You are currently viewing results with --severity-threshold=high applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_SeverityThresholdHighIssues(t *testing.T) {
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/4-high-5-medium.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
		WithLocalFindingsSeverityLevel("high"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.Contains(t, result, "[ 0 HIGH ]")
	require.Contains(t, result, "[ 4 HIGH ]")

	require.Contains(t, result, "You are currently viewing results with --severity-threshold applied")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_DefaultHideIgnored(t *testing.T) {
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
		WithLocalFindingsIgnoredIssues(false),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "src/main.ts, line 58")
}

func TestPresenterLocalFinding_IncludeIgnored(t *testing.T) {
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/with-ignores.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
		WithLocalFindingsIgnoredIssues(true),
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
	skipWindows(t)
	input, err := sarifToLocalFinding(t, "testdata/3-low-issues.json")
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := LocalFindingsTestResults(
		input,
		WithLocalFindingsOrg("test-org"),
		WithLocalFindingsTestPath("/path/to/project"),
		WithLocalFindingsIgnoredIssues(true),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_with_Issues(t *testing.T) {
	skipWindows(t)
	fd, err := os.Open("testdata/local-findings-juice-shop.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scannedPath := "path/to/project"
	p := LocalFindingsTestResults(localFindingDoc, WithLocalFindingsTestPath(scannedPath))

	result, err := p.Render()

	require.NoError(t, err)
	assert.Contains(t, result, "Total issues:   18")
	assert.Contains(t, result, "Static code analysis")
	assert.Contains(t, result, "╭")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterLocalFinding_with_severityFilter(t *testing.T) {
	skipWindows(t)

	fd, err := os.Open("testdata/local-findings-juice-shop.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	scannedPath := "path/to/project"
	p := LocalFindingsTestResults(
		localFindingDoc,
		WithLocalFindingsTestPath(scannedPath),
		WithLocalFindingsSeverityLevel("high"),
	)

	result, err := p.Render()

	require.NoError(t, err)
	assert.Contains(t, result, "You are currently viewing results with --severity-threshold applied")
	assert.Contains(t, result, "To view all issues, remove the --severity-threshold flag")
	snaps.MatchSnapshot(t, result)
}
