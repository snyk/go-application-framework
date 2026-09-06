package toon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters/toon"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

func TestProjectSections_supportedTypesOnly(t *testing.T) {
	t.Parallel()

	results := loadTestResults(t, "../testdata/ufm/sca.toon.testresult.json")
	sections, err := toon.ProjectSections(results, []testapi.FindingType{testapi.FindingTypeSca, testapi.FindingTypeSast})
	require.NoError(t, err)
	require.Len(t, sections, 1)
	assert.Equal(t, "sca", sections[0].Name)
	assert.Len(t, sections[0].Rows, 3)
}

func TestProjectSections_orderAndPairing(t *testing.T) {
	t.Parallel()

	results := loadTestResults(t, "../testdata/ufm/secrets.toon.testresult.json")
	sections, err := toon.ProjectSections(results, []testapi.FindingType{testapi.FindingTypeSecrets, testapi.FindingTypeSca})
	require.NoError(t, err)
	require.Len(t, sections, 2)
	assert.Equal(t, "sca", sections[0].Name)
	assert.Equal(t, "secrets", sections[1].Name)
}
