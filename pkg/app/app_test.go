package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
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

func Test_initConfiguration_updateDefaultOrgId(t *testing.T) {
	orgName := "someOrgName"
	orgId := "someOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetOrgIdFromSlug(orgName).Return(orgId, nil).AnyTimes()
	mockApiClient.EXPECT().GetSlugFromOrgId(orgId).Return(orgName, nil).AnyTimes()

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	initConfiguration(engine, config, mockApiClient, &zlog.Logger)

	config.Set(configuration.ORGANIZATION, orgName)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	actualOrgSlug := config.GetString(configuration.ORGANIZATION_SLUG)
	assert.Equal(t, orgId, actualOrgId)
	assert.Equal(t, orgName, actualOrgSlug)
}

func Test_initConfiguration_useDefaultOrg(t *testing.T) {
	defaultOrgId := "someDefaultOrgId"
	defaultOrgSlug := "someDefaultOrgSlug"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetDefaultOrgId().Return(defaultOrgId, nil).AnyTimes()
	mockApiClient.EXPECT().GetSlugFromOrgId(defaultOrgId).Return(defaultOrgSlug, nil).AnyTimes()

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	initConfiguration(engine, config, mockApiClient, &zlog.Logger)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	actualOrgSlug := config.GetString(configuration.ORGANIZATION_SLUG)
	assert.Equal(t, defaultOrgId, actualOrgId)
	assert.Equal(t, defaultOrgSlug, actualOrgSlug)
}

func Test_initConfiguration_useDefaultOrgAsFallback(t *testing.T) {
	orgName := "someOrgName"
	defaultOrgId := "someDefaultOrgId"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetOrgIdFromSlug(orgName).Return("", errors.New("Failed to fetch org id from slug")).AnyTimes()
	mockApiClient.EXPECT().GetDefaultOrgId().Return(defaultOrgId, nil).AnyTimes()
	mockApiClient.EXPECT().GetSlugFromOrgId(defaultOrgId).Return(orgName, nil).AnyTimes()

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	initConfiguration(engine, config, mockApiClient, &zlog.Logger)

	config.Set(configuration.ORGANIZATION, orgName)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	actualOrgSlug := config.GetString(configuration.ORGANIZATION_SLUG)
	assert.Equal(t, defaultOrgId, actualOrgId)
	assert.Equal(t, orgName, actualOrgSlug)
}

func Test_initConfiguration_uuidOrgId(t *testing.T) {
	orgId := "0d2bc57c-1df9-4115-996f-4f19aa12912b"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	// mock assertion
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).Times(1)

	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	initConfiguration(engine, config, mockApiClient, &zlog.Logger)

	config.Set(configuration.ORGANIZATION, orgId)

	actualOrgId := config.GetString(configuration.ORGANIZATION)
	assert.Equal(t, actualOrgId, orgId)
}

func Test_CreateAppEngineWithLogger(t *testing.T) {
	logger := &zlog.Logger

	engine := CreateAppEngineWithOptions(WithZeroLogger(logger))

	assert.NotNil(t, engine)
	assert.Equal(t, logger, engine.GetLogger())
}

func Test_CreateAppEngineWithConfigAndLoggerOptions(t *testing.T) {
	logger := &zlog.Logger
	config := configuration.NewInMemory()

	engine := CreateAppEngineWithOptions(WithZeroLogger(logger), WithConfiguration(config))

	assert.NotNil(t, engine)
	assert.Equal(t, logger, engine.GetLogger())
	assert.Equal(t, config, engine.GetConfiguration())
}

func Test_CreateAppEngineWithRuntimeInfo(t *testing.T) {
	ri := runtimeinfo.New(
		runtimeinfo.WithName("some-app"),
		runtimeinfo.WithVersion("some.version"))
	engine := CreateAppEngineWithOptions(WithRuntimeInfo(ri))

	assert.NotNil(t, engine)
	assert.Equal(t, ri, engine.GetRuntimeInfo())
}

func Test_initConfiguration_snykgov(t *testing.T) {
	endpoint := "https://snykgov.io"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	config := configuration.NewInMemory()
	initConfiguration(workflow.NewWorkFlowEngine(config), config, mockApiClient, &zlog.Logger)

	config.Set(configuration.API_URL, endpoint)

	actualOAuthFF := config.GetBool(configuration.FF_OAUTH_AUTH_FLOW_ENABLED)
	assert.True(t, actualOAuthFF)

	isFedramp := config.GetBool(configuration.IS_FEDRAMP)
	assert.True(t, isFedramp)
}

func Test_initConfiguration_NOT_snykgov(t *testing.T) {
	endpoint := "https://api.eu.snyk.io"

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)

	config := configuration.NewInMemory()
	initConfiguration(workflow.NewWorkFlowEngine(config), config, mockApiClient, &zlog.Logger)

	config.Set(configuration.API_URL, endpoint)

	isFedramp := config.GetBool(configuration.IS_FEDRAMP)
	assert.False(t, isFedramp)
}

func Test_initConfiguration_FF_CODE_CONSISTENT_IGNORES(t *testing.T) {
	orgId := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION, orgId)

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()
	mockApiClient.EXPECT().GetFeatureFlag("snykCodeConsistentIgnores", orgId).Return(true, nil).Times(1)
	mockApiClient.EXPECT().GetFeatureFlag("snykCodeConsistentIgnores", orgId).Return(false, nil).Times(1)
	mockApiClient.EXPECT().GetFeatureFlag("snykCodeConsistentIgnores", orgId).Return(false, fmt.Errorf("error")).Times(1)

	initConfiguration(workflow.NewWorkFlowEngine(config), config, mockApiClient, &zlog.Logger)

	consistentIgnores := config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
	assert.True(t, consistentIgnores)

	consistentIgnores = config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
	assert.False(t, consistentIgnores)

	consistentIgnores = config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES)
	assert.False(t, consistentIgnores)
}

func Test_initConfiguration_PREVIEW_FEATURES_ENABLED(t *testing.T) {
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)

	// setup mock
	ctrl := gomock.NewController(t)
	mockApiClient := mocks.NewMockApiClient(ctrl)
	mockApiClient.EXPECT().Init(gomock.Any(), gomock.Any()).AnyTimes()

	initConfiguration(engine, config, mockApiClient, &zlog.Logger)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-preview.456")))
	actual := config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.True(t, actual)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-dev.456")))
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.True(t, actual)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3-rc.456")))
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.False(t, actual)

	engine.SetRuntimeInfo(runtimeinfo.New(runtimeinfo.WithVersion("1.2.3")))
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.False(t, actual)

	config.Set(configuration.PREVIEW_FEATURES_ENABLED, true)
	actual = config.GetBool(configuration.PREVIEW_FEATURES_ENABLED)
	assert.True(t, actual)
}
