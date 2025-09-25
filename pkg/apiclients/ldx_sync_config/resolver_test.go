package ldx_sync_config

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestTryResolveOrganization_Unit(t *testing.T) {
	logger := zerolog.Nop()

	// Setup a temporary git repository
	tempDir, err := os.MkdirTemp("", "test-git-repo")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tempDir
		err := cmd.Run()
		assert.NoError(t, err, fmt.Sprintf("failed to run command: %v", args))
	}

	runCmd("git", "init")
	runCmd("git", "remote", "add", "origin", "https://github.com/test/repo.git")

	// Test cases
	tests := []struct {
		name          string
		setupMock     func(*mocks.MockClientWithResponsesInterface)
		expectedOrgId string
		inputDir      string
	}{
		{
			name:          "empty input directory",
			setupMock:     func(mock *mocks.MockClientWithResponsesInterface) {},
			expectedOrgId: "",
			inputDir:      "",
		},
		{
			name: "successful resolution with PreferredByAlgorithm",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: &[]v20241015.FolderConfig{
											{
												Organizations: &[]v20241015.Organization{
													{Id: "org-default", IsDefault: boolPtr(true)},
													{Id: "org-preferred", PreferredByAlgorithm: boolPtr(true)},
												},
											},
										},
									},
								},
							},
						},
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			expectedOrgId: "org-preferred",
			inputDir:      tempDir,
		},
		{
			name: "successful resolution with default org when no preferred",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: &[]v20241015.FolderConfig{
											{
												Organizations: &[]v20241015.Organization{
													{Id: "org-default", IsDefault: boolPtr(true)},
													{Id: "org-other", IsDefault: boolPtr(false)},
												},
											},
										},
									},
								},
							},
						},
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			expectedOrgId: "org-default",
			inputDir:      tempDir,
		},
		{
			name: "no preferred or default org",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: &[]v20241015.FolderConfig{
											{
												Organizations: &[]v20241015.Organization{
													{Id: "org-1", IsDefault: boolPtr(false)},
													{Id: "org-2"},
												},
											},
										},
									},
								},
							},
						},
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "no organizations in response",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: &[]v20241015.FolderConfig{},
									},
								},
							},
						},
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "nil folderconfig in response",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: nil,
									},
								},
							},
						},
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "API error",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("API error"))
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "git remote detection fails",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				// No API call expected
			},
			expectedOrgId: "",
			inputDir:      "/tmp/non-existent-dir-for-git-fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockClientWithResponsesInterface(ctrl)
			tt.setupMock(mockClient)

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			config.Set(configuration.INPUT_DIRECTORY, tt.inputDir)

			result := TryResolveOrganization(config, mockClient, &logger)
			assert.Equal(t, tt.expectedOrgId, result)
		})
	}
}

// TestGetConfigWithMock tests the GetConfig function using generated mocks
// Note: This test is limited due to git dependency in getLdxSyncConfig
func TestGetConfigWithMock(t *testing.T) {
	logger := zerolog.Nop()

	tests := []struct {
		name          string
		inputDir      string
		setupMock     func(*mocks.MockClientWithResponsesInterface)
		expectedError string
	}{
		{
			name:     "empty input directory",
			inputDir: "",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				// No expectations needed as the function will return early
			},
			expectedError: "no input directory specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockClientWithResponsesInterface(ctrl)
			tt.setupMock(mockClient)

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			config.Set("INPUT_DIRECTORY", tt.inputDir)

			result, err := GetConfig(config, "", mockClient, &logger)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	logger := zerolog.Nop()

	tests := []struct {
		name          string
		inputDir      string
		setupMock     func(*mocks.MockClientWithResponsesInterface)
		expectedError string
	}{
		{
			name:     "empty input directory",
			inputDir: "",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				// No expectations needed as the function will return early
			},
			expectedError: "no input directory specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockClientWithResponsesInterface(ctrl)
			tt.setupMock(mockClient)

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			config.Set("INPUT_DIRECTORY", tt.inputDir)

			result, err := GetConfig(config, "", mockClient, &logger)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			}
		})
	}
}

func TestGetLdxSyncConfig(t *testing.T) {
	tests := []struct {
		name          string
		inputDir      string
		setupMock     func(*mocks.MockClientWithResponsesInterface)
		expectedError string
	}{
		{
			name:     "empty input directory",
			inputDir: "",
			setupMock: func(mock *mocks.MockClientWithResponsesInterface) {
				// No expectations needed as the function will return early
			},
			expectedError: "no input directory specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockClient := mocks.NewMockClientWithResponsesInterface(ctrl)
			tt.setupMock(mockClient)

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			config.Set("INPUT_DIRECTORY", tt.inputDir)

			result := getLdxSyncConfig(config, mockClient, "")

			if tt.expectedError != "" {
				assert.Error(t, result.Error)
				assert.Contains(t, result.Error.Error(), tt.expectedError)
			}
		})
	}
}

// Helper function to create bool pointers
func boolPtr(b bool) *bool {
	return &b
}
