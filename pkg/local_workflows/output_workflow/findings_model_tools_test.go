package output_workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
)

func getLocalFindingsSkeleton(t *testing.T, count uint32) []*local_models.LocalFinding {
	t.Helper()

	localFindings := make([]*local_models.LocalFinding, 0)
	localFindings = append(localFindings, &local_models.LocalFinding{
		Summary: struct {
			Artifacts int                             `json:"artifacts"`
			Counts    local_models.TypesFindingCounts `json:"counts"`
			Coverage  []local_models.TypesCoverage    `json:"coverage"`
			Path      string                          `json:"path"`
			Type      string                          `json:"type"`
		}{},
	})
	localFindings[0].Summary.Counts.Count = count
	return localFindings
}

func Test_getTotalNumberOfFindings(t *testing.T) {
	t.Run("nil findings", func(t *testing.T) {
		expectedCount := uint32(0)
		var localFindings []*local_models.LocalFinding

		// method under test
		actualCount := getTotalNumberOfFindings(localFindings)
		assert.Equal(t, expectedCount, actualCount)
	})

	t.Run("count multiple findings", func(t *testing.T) {
		expectedCount := uint32(8)
		localFindings := getLocalFindingsSkeleton(t, 2)
		localFindings = append(localFindings, getLocalFindingsSkeleton(t, 6)...)

		// method under test
		actualCount := getTotalNumberOfFindings(localFindings)
		assert.Equal(t, expectedCount, actualCount)
	})
}

func Test_getSarifFileRenderer(t *testing.T) {
	t.Run("no file path specified", func(t *testing.T) {
		localFindings := getLocalFindingsSkeleton(t, 3)
		config := configuration.NewWithOpts()
		renderer, err := getSarifFileRenderer(config, localFindings)
		assert.NoError(t, err)
		assert.Nil(t, renderer)
	})

	t.Run("write empty file", func(t *testing.T) {
		localFindings := getLocalFindingsSkeleton(t, 0)
		config := configuration.NewWithOpts()
		config.Set(OUTPUT_CONFIG_KEY_SARIF_FILE, t.TempDir()+"/somefile")
		config.Set(OUTPUT_CONFIG_WRITE_EMPTY_FILE, true)
		renderer, err := getSarifFileRenderer(config, localFindings)
		assert.NoError(t, err)
		assert.NotNil(t, renderer)
		assert.NoError(t, renderer.closer())
	})

	t.Run("write non empty file", func(t *testing.T) {
		localFindings := getLocalFindingsSkeleton(t, 1)
		config := configuration.NewWithOpts()
		config.Set(OUTPUT_CONFIG_KEY_SARIF_FILE, t.TempDir()+"/somefile")
		config.Set(OUTPUT_CONFIG_WRITE_EMPTY_FILE, false)
		renderer, err := getSarifFileRenderer(config, localFindings)
		assert.NoError(t, err)
		assert.NotNil(t, renderer)
		assert.NoError(t, renderer.closer())
	})

	t.Run("don't write empty file", func(t *testing.T) {
		localFindings := getLocalFindingsSkeleton(t, 0)
		config := configuration.NewWithOpts()
		config.Set(OUTPUT_CONFIG_KEY_SARIF_FILE, t.TempDir()+"/somefile")
		config.Set(OUTPUT_CONFIG_WRITE_EMPTY_FILE, false)
		renderer, err := getSarifFileRenderer(config, localFindings)
		assert.NoError(t, err)
		assert.Nil(t, renderer)
	})
}
