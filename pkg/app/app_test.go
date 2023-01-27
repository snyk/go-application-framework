package app

import (
	"testing"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func Test_CreateAppEngine(t *testing.T) {
	engine := CreateAppEngine()
	assert.NotNil(t, engine)

	err := engine.Init()
	assert.Nil(t, err)

	expectApiUrl := constants.SNYK_DEFAULT_API_URL
	actualApiUrl := engine.GetConfiguration().GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)
}

func Test_CreateAppEngine_config_replaceV1inApi(t *testing.T) {
	engine := CreateAppEngine()
	assert.NotNil(t, engine)

	err := engine.Init()
	assert.Nil(t, err)

	config := engine.GetConfiguration()

	expectApiUrl := "https://somehost:2134/api"
	config.Set(configuration.API_URL, expectApiUrl+"/v1")

	actualApiUrl := config.GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)

	t.Run("should set DepGraphWorkflow defaults", func(t *testing.T) {
		allProjects := config.Get("all-projects")
		assert.Equal(t, allProjects, false)

		inputFile := config.Get("file")
		assert.Equal(t, inputFile, "")
	})

	t.Run("should set OutputWorkflow defaults", func(t *testing.T) {
		json := config.Get("json")
		assert.Equal(t, json, false)

		jsonFileOutput := config.Get("json-file-output")
		assert.Equal(t, jsonFileOutput, "")
	})
}
