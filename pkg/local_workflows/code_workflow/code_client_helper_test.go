package code_workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_GetReportType(t *testing.T) {
	config := configuration.NewWithOpts()
	assert.Equal(t, noReport, GetReportMode(config))

	config.Set(ConfigurationReportFlag, true)
	assert.Equal(t, localCode, GetReportMode(config))

	config.Set(ConfigurationProjectName, "hello")
	assert.Equal(t, remoteCode, GetReportMode(config))

	config.Set(ConfigurationReportFlag, false)
	assert.Equal(t, noReport, GetReportMode(config))
}
