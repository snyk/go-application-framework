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
	ldx_mocks "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestResolveOrganization(t *testing.T) {
	logger := zerolog.Nop()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)

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
		name                string
		setupMock           func(mock *ldx_mocks.MockClientWithResponsesInterface)
		setupClientCreation func()
		expectedOrgId       string
		inputDir            string
	}{
		{
			name:          "empty input directory",
			setupMock:     func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			expectedOrgId: "",
			inputDir:      "",
		},
		{
			name: "successful resolution with PreferredByAlgorithm",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
													{Id: "org-preferred", PreferredByAlgorithm: boolPtr(true)},
												},
											},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-default", IsDefault: boolPtr(true)},
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
			name: "successful resolution using ApplicationvndApiJSON200 response",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						ApplicationvndApiJSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: &[]v20241015.FolderConfig{
											{
												Organizations: &[]v20241015.Organization{
													{Id: "org-preferred-vnd", PreferredByAlgorithm: boolPtr(true)},
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
			expectedOrgId: "org-preferred-vnd",
			inputDir:      tempDir,
		},
		{
			name: "fallback to default org when no preferred",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
													{Id: "org-other", PreferredByAlgorithm: boolPtr(false)},
												},
											},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-default", IsDefault: boolPtr(true)},
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
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
													{Id: "org-1", PreferredByAlgorithm: boolPtr(false)},
													{Id: "org-2"},
												},
											},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-3", IsDefault: boolPtr(false)},
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
			name: "no organizations in folder config, fallback to default",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: &[]v20241015.FolderConfig{
											{},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-default", IsDefault: boolPtr(true)},
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
			name: "nil folderconfig in response, fallback to default",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON200: &v20241015.ConfigResponse{
							Data: v20241015.ConfigResource{
								Attributes: v20241015.ConfigAttributes{
									ConfigData: v20241015.ConfigData{
										FolderConfigs: nil,
										Organizations: &[]v20241015.Organization{
											{Id: "org-default", IsDefault: boolPtr(true)},
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
			name: "API error",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("API error"))
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "API returns 404",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON404:      &v20241015.ErrorResponseApplicationJSON{},
						HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
					}, nil)
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "API returns 200 with no data",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			expectedOrgId: "",
			inputDir:      tempDir,
		},
		{
			name: "git remote detection fails",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				// No API call expected
			},
			expectedOrgId: "",
			inputDir:      "/tmp/non-existent-dir-for-git-fail",
		},
		{
			name:          "client creation fails",
			setupMock:     func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			expectedOrgId: "",
			inputDir:      tempDir,
			setupClientCreation: func() {
				newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
					return nil, errors.New("client creation failed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockLdxClient := ldx_mocks.NewMockClientWithResponsesInterface(ctrl)
			if tt.setupMock != nil {
				tt.setupMock(mockLdxClient)
			}

			// Default client creation mock
			newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
				return mockLdxClient, nil
			}
			if tt.setupClientCreation != nil {
				tt.setupClientCreation()
			}
			defer func() { newClient = newClientImpl }()

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())

			result := ResolveOrganization(config, mockEngine, &logger, tt.inputDir)
			assert.Equal(t, tt.expectedOrgId, result)
		})
	}
}

// Helper function to create bool pointers
func boolPtr(b bool) *bool {
	return &b
}
