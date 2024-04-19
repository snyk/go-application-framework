package presenters_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/stretchr/testify/require"
)

var testMeta = presenters.TestMeta{
	OrgName:  "test-org",
	TestPath: "/path/to/project",
}

func TestPresenterSarifResultsPretty_NoIssues(t *testing.T) {
	fd, err := os.Open("testdata/no-issues.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, false, true)

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
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, false, true)

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
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, false, true)

	require.Nil(t, err)
	snaps.MatchSnapshot(t, result)
}

func TestPresenterSarifResultsPretty_MediumHighIssuesWithColor(t *testing.T) {
	fd, err := os.Open("testdata/4-high-5-medium.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.TrueColor)
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, false, true)

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
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, false, true)

	require.Nil(t, err)
	require.NotContains(t, result, "Path: src/main.ts, line 58")
}

func TestPresenterSarifResultsPretty_IncludeIgnored(t *testing.T) {
	fd, err := os.Open("testdata/with-ignores.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, true, true)

	require.Nil(t, err)
	require.Contains(t, result, "[ IGNORED ] [MEDIUM]")
	require.Contains(t, result, "Path: src/main.ts, line 58")
	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.Contains(t, result, "To view ignored issues only, use the --only-ignores option.")
}

func TestPresenterSarifResultsPretty_OnlyIgnored(t *testing.T) {
	fd, err := os.Open("testdata/with-ignores.json")
	require.Nil(t, err)

	var input sarif.SarifDocument

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	lipgloss.SetColorProfile(termenv.Ascii)
	result, err := presenters.PresenterSarifResultsPretty(input, testMeta, true, false)

	require.Nil(t, err)
	require.Contains(t, result, "[ IGNORED ] [MEDIUM]")
	require.Contains(t, result, "Path: src/main.ts, line 58")
	require.Contains(t, result, "Ignored Issues")
	require.Contains(t, result, "Ignores are currently managed in the Snyk Web UI.")
	require.Contains(t, result, "To view ignored and open issues, use the --include-ignores option.")
}
