package presenters_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMeta = presenters.TestMeta{
	OrgName:  "test-org",
	TestPath: "/path/to/project",
}

func TestPresenterSarifResultsPretty_NoIssues(t *testing.T) {
	fd, err := os.Open("testdata/no-issues.json")
	require.Nil(t, err)

	var input presenters.SarifResults

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	expected, err := os.ReadFile("testdata/no-issues.txt")
	require.Nil(t, err)

	result, err := presenters.PresenterSarifResultsPretty(input, testMeta)

	require.Nil(t, err)
	assert.Equal(t, string(expected), result)
}

func TestPresenterSarifResultsPretty_LowIssues(t *testing.T) {
	fd, err := os.Open("testdata/3-low-issues.json")
	require.Nil(t, err)

	var input presenters.SarifResults

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	expected, err := os.ReadFile("testdata/3-low-issues.txt")
	require.Nil(t, err)

	result, err := presenters.PresenterSarifResultsPretty(input, testMeta)

	require.Nil(t, err)
	assert.Equal(t, strings.Split(string(expected), "\n"), strings.Split(result, "\n"))
}

func TestPresenterSarifResultsPretty_MediumHighIssues(t *testing.T) {
	fd, err := os.Open("testdata/4-high-5-medium.json")
	require.Nil(t, err)

	var input presenters.SarifResults

	err = json.NewDecoder(fd).Decode(&input)
	require.Nil(t, err)

	expected, err := os.ReadFile("testdata/4-high-5-medium.txt")
	require.Nil(t, err)

	result, err := presenters.PresenterSarifResultsPretty(input, testMeta)

	require.Nil(t, err)
	assert.Equal(t, strings.Split(string(expected), "\n"), strings.Split(result, "\n"))
}
