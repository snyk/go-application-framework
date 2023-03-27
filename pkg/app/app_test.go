package app

import (
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/mocks"
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

	expectApiUrl := "https://api.somehost:2134"
	config.Set(configuration.API_URL, expectApiUrl+"/v1")

	actualApiUrl := config.GetString(configuration.API_URL)
	assert.Equal(t, expectApiUrl, actualApiUrl)
}

func Test_CreateAppEngine_oAuthEnvVarOverridesAuthFlow(t *testing.T) {
	for _, envVar := range []string{"SNYK_TOKEN", "SNYK_OAUTH_TOKEN", "SNYK_DOCKER_TOKEN"} {
		t.Run(fmt.Sprintf("For %s envVar", envVar), func(t *testing.T) {
			// loop through all env vars that can be used for authentication
			engine := CreateAppEngine()
			assert.NotNil(t, engine)

			config := engine.GetConfiguration()
			config.Set(configuration.OAUTH_AUTH_FLOW_ENABLED, true)
			assert.Equal(t, true, config.GetBool(configuration.OAUTH_AUTH_FLOW_ENABLED))

			// setting this env var should override the config
			os.Setenv(envVar, "token")
			assert.Equal(t, false, config.GetBool(configuration.OAUTH_AUTH_FLOW_ENABLED))
			os.Unsetenv(envVar)
		})
	}
}

func Test_initConfiguration_updateDefaultOrgId(t *testing.T) {
	orgName := "someOrgName"
	orgId := "someOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).Times(1)
	mockApiClient.EXPECT().GetOrgIdFromSlug(orgName).Return(orgId, nil).Times(1)

	config := configuration.New()
	initConfiguration(config, mockApiClient, log.Default())

	config.Set(configuration.ORGANIZATION, orgName)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	assert.Equal(t, orgId, actualOrgId)
}

func Test_initConfiguration_useDefaultOrgId(t *testing.T) {
	defaultOrgId := "someDefaultOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).Times(1)
	mockApiClient.EXPECT().GetDefaultOrgId().Return(defaultOrgId, nil).Times(1)

	config := configuration.New()
	initConfiguration(config, mockApiClient, log.Default())

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	assert.Equal(t, defaultOrgId, actualOrgId)
}

func Test_initConfiguration_useDefaultOrgIdWhenGetOrgIdFromSlugFails(t *testing.T) {
	orgName := "someOrgName"
	defaultOrgId := "someDefaultOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).Times(1)
	mockApiClient.EXPECT().GetOrgIdFromSlug(orgName).Return("", errors.New("Failed to fetch org id from slug")).Times(1)
	mockApiClient.EXPECT().GetDefaultOrgId().Return(defaultOrgId, nil).Times(1)

	config := configuration.New()
	initConfiguration(config, mockApiClient, log.Default())

	config.Set(configuration.ORGANIZATION, orgName)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	assert.Equal(t, defaultOrgId, actualOrgId)
}

func Test_initConfiguration_uuidOrgId(t *testing.T) {
	orgId := "0d2bc57c-1df9-4115-996f-4f19aa12912b"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).Times(1)

	config := configuration.New()
	initConfiguration(config, mockApiClient, log.Default())

	config.Set(configuration.ORGANIZATION, orgId)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	assert.Equal(t, actualOrgId, orgId)
}
