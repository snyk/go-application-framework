package presenters

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPresenterLocalFinding_NoIssues(t *testing.T) {
	fd, err := os.Open("testdata/local-findings-empty.json")
	require.NoError(t, err)

	var localFindingDoc local_models.LocalFinding
	err = json.NewDecoder(fd).Decode(&localFindingDoc)
	require.NoError(t, err)

	p := LocalFindingPresenter(
		localFindingDoc)

	result, err := p.Render()

	require.NoError(t, err)
	assert.Equal(t, "", result)
}
