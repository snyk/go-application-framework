package localworkflows

import (
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_ConfigEnvironment_determineUrlFromAlias(t *testing.T) {
	envUrl, envErr := determineUrlFromAlias("SNYK-US-01")
	assert.NoError(t, envErr)
	assert.NotEmpty(t, envUrl)

	envUrl, envErr = determineUrlFromAlias("https://api.my.url.com")
	assert.NoError(t, envErr)
	assert.NotEmpty(t, envUrl)

	envUrl, envErr = determineUrlFromAlias("eu")
	assert.NoError(t, envErr)
	assert.NotEmpty(t, envUrl)

	envUrl, envErr = determineUrlFromAlias("totalNonSense")
	assert.Error(t, envErr)
	assert.Empty(t, envUrl)
}

func Test_ConfigEnvironment_entryPoint_changeEnv(t *testing.T) {
	var inputData []workflow.Data
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	logger := zerolog.New(io.Discard)

	config.Set(configuration.INPUT_DIRECTORY, "dev")
	config.Set(configuration.API_URL, "random")

	mockctl := gomock.NewController(t)
	storage := mocks.NewMockStorage(mockctl)
	config.SetStorage(storage)

	storage.EXPECT().Set(configuration.API_URL, gomock.Any())
	storage.EXPECT().Set(configuration.AUTHENTICATION_TOKEN, gomock.Any())
	storage.EXPECT().Set(auth.CONFIG_KEY_OAUTH_TOKEN, gomock.Any())
	storage.EXPECT().Set(configuration.ORGANIZATION, gomock.Any())

	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(config)
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger)
	invocationCtx.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	err := InitConfigWorkflow(engine)
	assert.NoError(t, err)

	outputData, outputErr := configEnvironmentWorkflowEntryPoint(invocationCtx, inputData)
	assert.Nil(t, outputData)
	assert.NoError(t, outputErr)
}

func Test_ConfigEnvironment_entryPoint_NoChangeEnv(t *testing.T) {
	var inputData []workflow.Data
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	logger := zerolog.New(io.Discard)

	config.Set(configuration.INPUT_DIRECTORY, "dev")
	config.Set(configuration.API_URL, "https://api.dev.snyk.io")

	mockctl := gomock.NewController(t)
	storage := mocks.NewMockStorage(mockctl)
	config.SetStorage(storage)

	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(config)
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger)
	invocationCtx.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	err := InitConfigWorkflow(engine)
	assert.NoError(t, err)

	outputData, outputErr := configEnvironmentWorkflowEntryPoint(invocationCtx, inputData)
	assert.Nil(t, outputData)
	assert.NoError(t, outputErr)
}

func Test_ConfigEnvironment_entryPoint_Failed(t *testing.T) {
	var inputData []workflow.Data
	config := configuration.NewInMemory()
	engine := workflow.NewWorkFlowEngine(config)
	logger := zerolog.New(io.Discard)

	config.Set(configuration.INPUT_DIRECTORY, "random")
	config.Set(configuration.API_URL, "https://api.dev.snyk.io")

	mockctl := gomock.NewController(t)
	storage := mocks.NewMockStorage(mockctl)
	config.SetStorage(storage)

	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(config)
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger)
	invocationCtx.EXPECT().GetUserInterface().Return(ui.DefaultUi())

	err := InitConfigWorkflow(engine)
	assert.NoError(t, err)

	outputData, outputErr := configEnvironmentWorkflowEntryPoint(invocationCtx, inputData)
	assert.Nil(t, outputData)
	assert.Error(t, outputErr)
}
