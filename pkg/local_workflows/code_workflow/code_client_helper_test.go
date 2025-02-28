package code_workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_GetReportType(t *testing.T) {
	t.Run("no repport", func(t *testing.T) {
		config := configuration.NewWithOpts()
		actualMode, err := GetReportMode(config)
		assert.Equal(t, noReport, actualMode)
		assert.NoError(t, err)
	})

	t.Run("remote report", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectId, "remote")
		config.Set(ConfigurationCommitId, "commit")
		actualMode, err := GetReportMode(config)
		assert.Equal(t, remoteCode, actualMode)
		assert.NoError(t, err)
	})

	t.Run("remote report with error", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectId, "remote")
		actualMode, err := GetReportMode(config)
		assert.Equal(t, noReport, actualMode)
		assert.Error(t, err)
	})

	t.Run("local report", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectName, "hello")
		actualMode, err := GetReportMode(config)
		assert.Equal(t, localCode, actualMode)
		assert.NoError(t, err)
	})

	t.Run("local report with error", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		actualMode, err := GetReportMode(config)
		assert.Equal(t, noReport, actualMode)
		assert.Error(t, err)
	})
}
