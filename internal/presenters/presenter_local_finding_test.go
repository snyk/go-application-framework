package presenters

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"

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
