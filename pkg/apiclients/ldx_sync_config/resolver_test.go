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
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api"
	api_mocks "github.com/snyk/go-application-framework/internal/mocks"
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
		setupApiMock        func(mock *api_mocks.MockApiClient)
		setupClientCreation func()
		expectedOrgId       string
		expectedErr         error
		inputDir            string
	}{
		{
			name:          "empty input directory",
			setupMock:     func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
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
													{Id: "org-preferred", PreferredByAlgorithm: utils.Ptr(true)},
												},
											},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-default", IsDefault: utils.Ptr(true)},
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
													{Id: "org-preferred-vnd", PreferredByAlgorithm: utils.Ptr(true)},
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
													{Id: "org-other", PreferredByAlgorithm: utils.Ptr(false)},
												},
											},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-default", IsDefault: utils.Ptr(true)},
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
			name: "no preferred or default org, fallback to api",
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
													{Id: "org-1", PreferredByAlgorithm: utils.Ptr(false)},
													{Id: "org-2"},
												},
											},
										},
										Organizations: &[]v20241015.Organization{
											{Id: "org-3", IsDefault: utils.Ptr(false)},
										},
									},
								},
							},
						},
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
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
											{Id: "org-default", IsDefault: utils.Ptr(true)},
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
											{Id: "org-default", IsDefault: utils.Ptr(true)},
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
			name: "API error, fallback to api",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("API error"))
			},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			inputDir:      tempDir,
		},
		{
			name: "API returns 404, fallback to api",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						JSON404:      &v20241015.ErrorResponseApplicationJSON{},
						HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
					}, nil)
			},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			inputDir:      tempDir,
		},
		{
			name: "API returns 200 with no data, fallback to api",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(&v20241015.GetConfigResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
					}, nil)
			},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			inputDir:      tempDir,
		},
		{
			name: "git remote detection fails, fallback to api",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				// No API call expected
			},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			inputDir:      "/tmp/non-existent-dir-for-git-fail",
		},
		{
			name:          "client creation fails, fallback to api",
			setupMock:     func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			inputDir:      tempDir,
			setupClientCreation: func() {
				newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
					return nil, errors.New("client creation failed")
				}
			},
		},
		{
			name: "LDX fails, fallback to API default org fails",
			setupMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().
					GetConfigWithResponse(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("ldx api error"))
			},
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetDefaultOrgId().Return("", errors.New("api is down"))
			},
			expectedOrgId: "",
			expectedErr:   errors.New("api is down"),
			inputDir:      tempDir,
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

			mockApiClient := api_mocks.NewMockApiClient(ctrl)
			if tt.setupApiMock != nil {
				tt.setupApiMock(mockApiClient)
			}

			newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
				return mockLdxClient, nil
			}
			newApiClient = func(_ workflow.Engine, _ configuration.Configuration) api.ApiClient {
				return mockApiClient
			}
			if tt.setupClientCreation != nil {
				tt.setupClientCreation()
			}

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())

			result, err := ResolveOrganization(config, mockEngine, &logger, tt.inputDir)
			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedOrgId, result.Id)
		})
	}
}
