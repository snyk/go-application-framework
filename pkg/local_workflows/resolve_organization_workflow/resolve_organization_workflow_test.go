package resolve_organization_workflow

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
	"github.com/stretchr/testify/require"

	api_mocks "github.com/snyk/go-application-framework/internal/mocks"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	ldx_mocks "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func setupMockResolveOrgContext(t *testing.T) *mocks.MockInvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	config := configuration.New()
	logger := zerolog.Logger{}

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvCtx := mocks.NewMockInvocationContext(ctrl)

	mockInvCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockInvCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockInvCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

	return mockInvCtx
}

func Test_InitResolveOrganizationWorkflow_RegistersWorkflow(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().Register(WORKFLOWID_RESOLVE_ORGANIZATION, gomock.Any(), gomock.Any()).Return(nil, nil)

	err := InitResolveOrganizationWorkflow(mockEngine)
	assert.NoError(t, err)
}

func Test_resolveOrganizationWorkflowEntryPointDI_ValidatesDirectory(t *testing.T) {
	mockInvCtx := setupMockResolveOrgContext(t)

	input := ResolveOrganizationInput{
		Directory: "",
	}
	inputData := createWorkflowInputData(t, input)

	_, err := resolveOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{inputData}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory is required")
}

func Test_resolveOrganizationWorkflowEntryPointDI_NoInput(t *testing.T) {
	mockInvCtx := setupMockResolveOrgContext(t)

	_, err := resolveOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no input provided")
}

func Test_resolveOrganizationWorkflowEntryPointDI_InvalidInputPayload(t *testing.T) {
	mockInvCtx := setupMockResolveOrgContext(t)

	data := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_RESOLVE_ORGANIZATION, "invalid-test"),
		"application/go-struct",
		"invalid-not-struct",
	)

	_, err := resolveOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{data}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid input payload type")
}

func Test_resolveOrganizationWorkflowEntryPoint_Integration(t *testing.T) {
	// Setup a temporary git repository for tests that need it
	tempDir, err := os.MkdirTemp("", "test-git-repo")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tempDir
		err := cmd.Run()
		require.NoError(t, err, fmt.Sprintf("failed to run command: %v", args))
	}

	runCmd("git", "init")
	runCmd("git", "remote", "add", "origin", "https://github.com/test/repo.git")

	tests := []struct {
		name           string
		setupLdxMock   func(mock *ldx_mocks.MockClientWithResponsesInterface)
		setupApiMock   func(mock *api_mocks.MockApiClient)
		ldxClientError bool // If true, pass nil ldxClient to simulate creation failure
		expectedOrgId  string
		expectedErr    error
		inputDir       string
	}{
		{
			name:          "empty input directory",
			setupLdxMock:  func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			expectedOrgId: "",
			expectedErr:   errors.New("directory is required"),
			inputDir:      "",
		},
		{
			name: "successful resolution with PreferredByAlgorithm",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			expectedOrgId: "org-preferred",
			inputDir:      tempDir,
		},
		{
			name: "successful resolution using ApplicationvndApiJSON200 response",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			expectedOrgId: "org-preferred-vnd",
			inputDir:      tempDir,
		},
		{
			name: "fallback to default org when no preferred",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			expectedOrgId: "org-default",
			inputDir:      tempDir,
		},
		{
			name: "no preferred or default org, fallback to api",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			expectedOrgId: "org-default",
			inputDir:      tempDir,
		},
		{
			name: "nil folderconfig in response, fallback to default",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			expectedOrgId: "org-default",
			inputDir:      tempDir,
		},
		{
			name: "API error, fallback to api",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			name:          "git remote detection fails, fallback to api",
			setupLdxMock:  func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			inputDir:      "/tmp/non-existent-dir-for-git-fail",
		},
		{
			name:           "client creation fails, fallback to api",
			setupLdxMock:   func(mock *ldx_mocks.MockClientWithResponsesInterface) {},
			setupApiMock:   func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			ldxClientError: true, // Simulate LDX client creation failure
			expectedOrgId:  "default-org",
			inputDir:       tempDir,
		},
		{
			name: "LDX fails, fallback to API default org fails",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
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
			t.Cleanup(ctrl.Finish)

			// Setup mocks
			mockLdxClient := ldx_mocks.NewMockClientWithResponsesInterface(ctrl)
			mockApiClient := api_mocks.NewMockApiClient(ctrl)

			if tt.setupLdxMock != nil {
				tt.setupLdxMock(mockLdxClient)
			}
			if tt.setupApiMock != nil {
				tt.setupApiMock(mockApiClient)
			}

			// Setup workflow context
			mockInvCtx := setupMockResolveOrgContext(t)

			// Create input
			input := ResolveOrganizationInput{
				Directory: tt.inputDir,
			}
			inputData := createWorkflowInputData(t, input)

			// Determine which ldxClient to pass (nil if simulating error)
			var ldxClientToPass v20241015.ClientWithResponsesInterface
			if tt.ldxClientError {
				ldxClientToPass = nil
			} else {
				ldxClientToPass = mockLdxClient
			}

			// Execute workflow using DI function directly with mocks
			output, err := resolveOrganizationWorkflowEntryPointDI(
				mockInvCtx,
				[]workflow.Data{inputData},
				ldxClientToPass,
				mockApiClient,
			)

			// Verify results
			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Len(t, output, 1)

				// Parse output
				result, ok := output[0].GetPayload().(ResolveOrganizationOutput)
				require.True(t, ok, "output payload should be ResolveOrganizationOutput")

				assert.Equal(t, tt.expectedOrgId, result.Organization.Id)
			}
		})
	}
}

// Helper functions

func createWorkflowInputData(t *testing.T, input ResolveOrganizationInput) workflow.Data {
	t.Helper()

	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_RESOLVE_ORGANIZATION, "resolve-org-input"),
		"application/go-struct",
		input,
	)
}
