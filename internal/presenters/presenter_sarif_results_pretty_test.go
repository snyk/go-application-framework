package presenters_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters"
)

func TestPresenterSarifResultsPretty_NoIssues(t *testing.T) {
	fd, err := os.Open("testdata/no-issues.json")
	require.Nil(t, err)

	var sarifDocument sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&sarifDocument)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		sarifDocument,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_LowIssues(t *testing.T) {
	fd, err := os.Open("testdata/3-low-issues.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_MediumHighIssues(t *testing.T) {
	fd, err := os.Open("testdata/4-high-5-medium.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)

	require.Contains(t, result, "[ 0 HIGH  0 MEDIUM  0 LOW ]")
	require.Contains(t, result, "[ 4 HIGH  5 MEDIUM  0 LOW ]")
	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_MediumHighIssuesWithColor(t *testing.T) {
	fd, err := os.Open("testdata/4-high-5-medium.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_SeverityThresholdHighIssues(t *testing.T) {
	fd, err := os.Open("testdata/4-high-5-medium.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
		presenters.WithSeverityThershold("high"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_DefaultHideIgnored(t *testing.T) {
	fd, err := os.Open("testdata/with-ignores.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "src/main.ts, line 58")
}

func TestPresenterSarifResultsPretty_IncludeIgnored(t *testing.T) {
	fd, err := os.Open("testdata/with-ignores.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
		presenters.WithIgnored(true),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.Contains(t, result, "[ IGNORED ] [MEDIUM]")
	require.Contains(t, result, "src/main.ts, line 58")
	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.NotContains(t, result, "Empty ignore issues state")
	require.NotContains(t, result, "To view ignored and open issues, use the --include-ignores option.pre")

	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_IncludeIgnoredEmpty(t *testing.T) {
	fd, err := os.Open("testdata/3-low-issues.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	p := presenters.SarifTestResults(
		input,
		presenters.WithOrgName("test-org"),
		presenters.WithTestPath("/path/to/project"),
		presenters.WithIgnored(true),
	)

	result, err := p.Render()

	require.Nil(t, err)
	require.NotContains(t, result, "[ IGNORED ]")
	require.Contains(t, result, "There are no ignored issues")

	snaps.MatchSnapshot(t, result)
}

func TestFilterSeverityASC(t *testing.T) {
	input := []string{"low", "medium", "high", "critical"}

	t.Run("Threshold medium", func(t *testing.T) {
		expected := []string{"medium", "high", "critical"}
		actual := presenters.FilterSeverityASC(input, "medium")
		assert.Equal(t, expected, actual)
	})

	t.Run("Threshold critical", func(t *testing.T) {
		expected := []string{"critical"}
		actual := presenters.FilterSeverityASC(input, "critical")
		assert.Equal(t, expected, actual)
	})

	t.Run("Threshold unknown", func(t *testing.T) {
		expected := input
		actual := presenters.FilterSeverityASC(input, "unknown")
		assert.Equal(t, expected, actual)
	})
}
