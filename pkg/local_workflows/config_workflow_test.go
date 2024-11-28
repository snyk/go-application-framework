package localworkflows

import (
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_ConfigEnvironment_determineUrlFromAlias(t *testing.T) {
	defaultUrl, defaultErr := determineUrlFromAlias("default")
	assert.NoError(t, defaultErr)
	assert.Equal(t, "https://api.snyk.io", defaultUrl)

	envUrl, envErr := determineUrlFromAlias("SNYK-US-01")
	assert.NoError(t, envErr)
	assert.NotEmpty(t, envUrl)

	nonCanonicalizedUrl := "https://app.snyk.io/api"
	canonicalizedUrl, err := api.GetCanonicalApiUrlFromString(nonCanonicalizedUrl)
	envUrl, envErr = determineUrlFromAlias(nonCanonicalizedUrl)
	assert.NoError(t, err)
	assert.NoError(t, envErr)
	assert.NotEmpty(t, envUrl)
	assert.Equal(t, canonicalizedUrl, envUrl)

	nonCanonicalizedUrl = "https://app.random.io/api"
	envUrl, envErr = determineUrlFromAlias(nonCanonicalizedUrl)
	assert.Error(t, envErr)
	assert.Empty(t, envUrl)

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

func Test_DetermineRegionFromUrl(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{
			name:    "Empty URL",
			url:     "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "US Region 1",
			url:     "https://api.snyk.io/something",
			want:    "snyk-us-01",
			wantErr: false,
		},
		{
			name:    "US Region 2",
			url:     "https://api.us.snyk.io/something",
			want:    "snyk-us-02",
			wantErr: false,
		},
		{
			name:    "AU Region",
			url:     "https://api.au.snyk.io/something",
			want:    "snyk-au-01",
			wantErr: false,
		},
		{
			name:    "EU Region",
			url:     "https://api.eu.snyk.io/something",
			want:    "snyk-eu-01",
			wantErr: false,
		},
		{
			name:    "Gov Region",
			url:     "https://api.snykgov.io/something",
			want:    "snyk-gov-01",
			wantErr: false,
		},
		{
			name:    "Invalid URL",
			url:     "invalid_url",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Unknown Region",
			url:     "https://unknown.snyk.io/something",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetermineRegionFromUrl(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetermineRegionFromUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DetermineRegionFromUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}
