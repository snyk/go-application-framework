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

// Helper function to create a UserConfigResponse with organizations
func makeUserConfigResponse(orgs []v20241015.Organization) *v20241015.UserConfigResponse {
	response := &v20241015.UserConfigResponse{}
	response.Data.Attributes.Organizations = &orgs
	return response
}

func TestResolveOrgFromUserConfig(t *testing.T) {
	logger := zerolog.Nop()

	// Test cases
	tests := []struct {
		name          string
		setupApiMock  func(mock *api_mocks.MockApiClient)
		expectedOrgId string
		expectedErr   error
		cfgResult     LdxSyncConfigResult
	}{
		{
			name:          "error in config result",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult:     LdxSyncConfigResult{Error: fmt.Errorf("no input directory specified")},
		},
		{
			name:          "successful resolution with PreferredByAlgorithm",
			expectedOrgId: "org-preferred",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "org-preferred", PreferredByAlgorithm: utils.Ptr(true)},
					{Id: "org-default", IsDefault: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "successful resolution using ApplicationvndApiJSON200 response",
			expectedOrgId: "org-preferred-vnd",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "org-preferred-vnd", PreferredByAlgorithm: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "fallback to default org when no preferred",
			expectedOrgId: "org-default",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "org-other", PreferredByAlgorithm: utils.Ptr(false)},
					{Id: "org-default", IsDefault: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "no preferred or default org, fallback to api",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "org-1", PreferredByAlgorithm: utils.Ptr(false)},
					{Id: "org-2"},
					{Id: "org-3", IsDefault: utils.Ptr(false)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "no organizations in response, fallback to API",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult: LdxSyncConfigResult{
				Config:      makeUserConfigResponse([]v20241015.Organization{}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "nil organizations in response, fallback to API",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult: LdxSyncConfigResult{
				Config:      &v20241015.UserConfigResponse{},
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "API error, fallback to api",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult:     LdxSyncConfigResult{Error: errors.New("API error")},
		},
		{
			name:          "API returns 404, fallback to api",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult:     LdxSyncConfigResult{Error: fmt.Errorf("404 API error occurred")},
		},
		{
			name:          "API returns 200 with no data, fallback to api",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult:     LdxSyncConfigResult{Error: fmt.Errorf("no configuration data in response, status code: 200")},
		},
		{
			name:          "git remote detection fails, fallback to api",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult:     LdxSyncConfigResult{Error: fmt.Errorf("git remote detection failed: git command failed")},
		},
		{
			name:          "client creation fails, fallback to api",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult:     LdxSyncConfigResult{Error: fmt.Errorf("failed to create LDX-Sync client: client creation failed")},
		},
		{
			name:          "LDX-Sync returns preferred org",
			expectedOrgId: "123e4567-e89b-12d3-a456-426614174000",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "123e4567-e89b-12d3-a456-426614174000", PreferredByAlgorithm: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "LDX-Sync returns another preferred org",
			expectedOrgId: "ldx-preferred-org",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "ldx-preferred-org", PreferredByAlgorithm: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "LDX-Sync returns specific org as preferred",
			expectedOrgId: "33333333-3333-3333-3333-333333333333",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "33333333-3333-3333-3333-333333333333", PreferredByAlgorithm: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name:          "LDX-Sync preferred org from config",
			expectedOrgId: "ldx-preferred-from-slug",
			cfgResult: LdxSyncConfigResult{
				Config: makeUserConfigResponse([]v20241015.Organization{
					{Id: "ldx-preferred-from-slug", PreferredByAlgorithm: utils.Ptr(true)},
				}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: "/test/project",
			},
		},
		{
			name: "LDX fails, fallback to API default org fails",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetDefaultOrgId().Return("", errors.New("api is down"))
			},
			expectedOrgId: "",
			expectedErr:   errors.New("api is down"),
			cfgResult:     LdxSyncConfigResult{Error: errors.New("ldx api error")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockApiClient := api_mocks.NewMockApiClient(ctrl)
			if tt.setupApiMock != nil {
				tt.setupApiMock(mockApiClient)
			}

			newApiClient = func(_ workflow.Engine, _ configuration.Configuration) api.ApiClient {
				return mockApiClient
			}

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			mockEngine := mocks.NewMockEngine(ctrl)
			mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
			mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()

			result, err := ResolveOrgFromUserConfig(mockEngine, tt.cfgResult)
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

func TestGetUserConfigForProject(t *testing.T) {
	logger := zerolog.Nop()

	// Preserve original global variables and restore after tests
	origNewClient := newClient
	origNewApiClient := newApiClient
	defer func() {
		newClient = origNewClient
		newApiClient = origNewApiClient
	}()

	// Setup a temporary git repository
	tempDir, err := os.MkdirTemp("", "test-git-repo")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	runCmd := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tempDir
		err = cmd.Run()
		assert.NoError(t, err, fmt.Sprintf("failed to run command: %v", args))
	}

	runCmd("git", "init")
	runCmd("git", "remote", "add", "origin", "https://github.com/test/repo.git")

	// Setup a temp dir without git for git failure tests
	tempDirNoGit, err := os.MkdirTemp("", "test-no-git")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDirNoGit)

	// Test cases
	tests := []struct {
		name           string
		setupLdxMock   func(mock *ldx_mocks.MockClientWithResponsesInterface)
		setupApiMock   func(mock *api_mocks.MockApiClient)
		clientError    error
		dir            string
		orgId          string
		expectedError  string
		expectNoError  bool
		expectedConfig bool
		expectedOrgId  string // For response priority validation
	}{
		// Task 2: Error path test cases (empty dir, client failures, git failures)
		{
			name:          "empty directory parameter",
			dir:           "",
			expectedError: "no input directory specified",
		},
		{
			name:          "client creation failure",
			dir:           tempDir,
			clientError:   fmt.Errorf("client creation failed"),
			expectedError: "failed to create LDX-Sync client",
		},
		{
			name:          "git remote detection failure - no git init",
			dir:           tempDirNoGit,
			expectedError: "git remote detection failed",
		},
		{
			name:          "git remote empty string",
			dir:           tempDirNoGit,
			expectedError: "git remote detection failed",
		},
		// Task 3: OrgId resolution error path test cases
		{
			name:  "invalid orgId - bad UUID and slug resolution fails",
			dir:   tempDir,
			orgId: "invalid-org-id",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetOrgIdFromSlug("invalid-org-id").Return("", fmt.Errorf("slug not found"))
			},
			expectedError: "failed to resolve organization slug",
		},
		// Task 4: API error response test cases
		{
			name:  "GetUserConfigWithResponse returns error",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("network error"))
			},
			expectedError: "failed to retrieve LDX-Sync config",
		},
		{
			name:  "API returns 400 error",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(&v20241015.GetUserConfigResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusBadRequest},
					JSON400:      &v20241015.ErrorResponseApplicationJSON{},
				}, nil)
			},
			expectedError: "400 API error occurred",
		},
		{
			name:  "API returns 401 error",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(&v20241015.GetUserConfigResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusUnauthorized},
					JSON401:      &v20241015.ErrorResponseApplicationJSON{},
				}, nil)
			},
			expectedError: "401 API error occurred",
		},
		{
			name:  "API returns 404 error",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(&v20241015.GetUserConfigResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
					JSON404:      &v20241015.ErrorResponseApplicationJSON{},
				}, nil)
			},
			expectedError: "404 API error occurred",
		},
		{
			name:  "API returns 500 error",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(&v20241015.GetUserConfigResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusInternalServerError},
					JSON500:      &v20241015.ErrorResponseApplicationJSON{},
				}, nil)
			},
			expectedError: "500 API error occurred",
		},
		{
			name:  "API returns 501 error",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(&v20241015.GetUserConfigResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusNotImplemented},
					JSON501:      &v20241015.ErrorResponseApplicationJSON{},
				}, nil)
			},
			expectedError: "501 API error occurred",
		},
		{
			name:  "success response with no data",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(gomock.Any(), gomock.Any()).Return(&v20241015.GetUserConfigResponse{
					HTTPResponse: &http.Response{StatusCode: http.StatusOK},
				}, nil)
			},
			expectedError: "no configuration data in response",
		},
		// Task 5: Success path test cases (no orgId, UUID orgId)
		{
			name:  "no orgId with JSON200 response",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(
					gomock.Any(),
					gomock.AssignableToTypeOf(&v20241015.GetUserConfigParams{}),
				).DoAndReturn(func(ctx interface{}, params *v20241015.GetUserConfigParams, _ ...interface{}) (*v20241015.GetUserConfigResponse, error) {
					// Verify params
					assert.Equal(t, "2024-10-15", params.Version)
					assert.NotNil(t, params.Merged)
					assert.True(t, *params.Merged)
					assert.NotNil(t, params.RemoteUrl)
					assert.Equal(t, "https://github.com/test/repo.git", *params.RemoteUrl)
					assert.Nil(t, params.Org)
					return &v20241015.GetUserConfigResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
						JSON200:      makeUserConfigResponse([]v20241015.Organization{{Id: "org-1"}}),
					}, nil
				})
			},
			expectNoError:  true,
			expectedConfig: true,
		},
		{
			name:  "valid UUID orgId with JSON200 response",
			dir:   tempDir,
			orgId: "123e4567-e89b-12d3-a456-426614174000",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(
					gomock.Any(),
					gomock.AssignableToTypeOf(&v20241015.GetUserConfigParams{}),
				).DoAndReturn(func(ctx interface{}, params *v20241015.GetUserConfigParams, _ ...interface{}) (*v20241015.GetUserConfigResponse, error) {
					// Verify params
					assert.Equal(t, "2024-10-15", params.Version)
					assert.NotNil(t, params.Merged)
					assert.True(t, *params.Merged)
					assert.NotNil(t, params.RemoteUrl)
					assert.Equal(t, "https://github.com/test/repo.git", *params.RemoteUrl)
					assert.NotNil(t, params.Org)
					assert.Equal(t, "123e4567-e89b-12d3-a456-426614174000", params.Org.String())
					return &v20241015.GetUserConfigResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
						JSON200:      makeUserConfigResponse([]v20241015.Organization{{Id: "org-1"}}),
					}, nil
				})
			},
			expectNoError:  true,
			expectedConfig: true,
		},
		{
			name:  "valid UUID orgId with ApplicationvndApiJSON200 response",
			dir:   tempDir,
			orgId: "123e4567-e89b-12d3-a456-426614174000",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(
					gomock.Any(),
					gomock.AssignableToTypeOf(&v20241015.GetUserConfigParams{}),
				).DoAndReturn(func(ctx interface{}, params *v20241015.GetUserConfigParams, _ ...interface{}) (*v20241015.GetUserConfigResponse, error) {
					// Verify params
					assert.Equal(t, "2024-10-15", params.Version)
					assert.NotNil(t, params.Merged)
					assert.True(t, *params.Merged)
					assert.NotNil(t, params.RemoteUrl)
					assert.Equal(t, "https://github.com/test/repo.git", *params.RemoteUrl)
					assert.NotNil(t, params.Org)
					assert.Equal(t, "123e4567-e89b-12d3-a456-426614174000", params.Org.String())
					return &v20241015.GetUserConfigResponse{
						HTTPResponse:             &http.Response{StatusCode: http.StatusOK},
						ApplicationvndApiJSON200: makeUserConfigResponse([]v20241015.Organization{{Id: "org-1"}}),
					}, nil
				})
			},
			expectNoError:  true,
			expectedConfig: true,
		},
		// Task 6: Slug orgId resolution success test case
		{
			name:  "slug orgId requiring resolution with JSON200 response",
			dir:   tempDir,
			orgId: "my-org-slug",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetOrgIdFromSlug("my-org-slug").Return("123e4567-e89b-12d3-a456-426614174000", nil)
			},
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(
					gomock.Any(),
					gomock.AssignableToTypeOf(&v20241015.GetUserConfigParams{}),
				).DoAndReturn(func(ctx interface{}, params *v20241015.GetUserConfigParams, _ ...interface{}) (*v20241015.GetUserConfigResponse, error) {
					// Verify params including resolved orgId
					assert.Equal(t, "2024-10-15", params.Version)
					assert.NotNil(t, params.Merged)
					assert.True(t, *params.Merged)
					assert.NotNil(t, params.RemoteUrl)
					assert.Equal(t, "https://github.com/test/repo.git", *params.RemoteUrl)
					assert.NotNil(t, params.Org)
					assert.Equal(t, "123e4567-e89b-12d3-a456-426614174000", params.Org.String())
					return &v20241015.GetUserConfigResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusOK},
						JSON200:      makeUserConfigResponse([]v20241015.Organization{{Id: "org-1"}}),
					}, nil
				})
			},
			expectNoError:  true,
			expectedConfig: true,
		},
		// Test for response priority - JSON200 takes precedence over ApplicationvndApiJSON200
		{
			name:  "both JSON200 and ApplicationvndApiJSON200 present - JSON200 takes priority",
			dir:   tempDir,
			orgId: "",
			setupLdxMock: func(mock *ldx_mocks.MockClientWithResponsesInterface) {
				mock.EXPECT().GetUserConfigWithResponse(
					gomock.Any(),
					gomock.AssignableToTypeOf(&v20241015.GetUserConfigParams{}),
				).DoAndReturn(func(ctx interface{}, params *v20241015.GetUserConfigParams, _ ...interface{}) (*v20241015.GetUserConfigResponse, error) {
					return &v20241015.GetUserConfigResponse{
						HTTPResponse:             &http.Response{StatusCode: http.StatusOK},
						JSON200:                  makeUserConfigResponse([]v20241015.Organization{{Id: "org-from-json200"}}),
						ApplicationvndApiJSON200: makeUserConfigResponse([]v20241015.Organization{{Id: "org-from-vnd-api"}}),
					}, nil
				})
			},
			expectNoError:  true,
			expectedConfig: true,
			expectedOrgId:  "org-from-json200",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			mockEngine := mocks.NewMockEngine(ctrl)
			mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
			mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()

			// Setup client creation mock
			if tt.clientError != nil {
				newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
					return nil, tt.clientError
				}
			} else if tt.setupLdxMock != nil {
				mockLdxClient := ldx_mocks.NewMockClientWithResponsesInterface(ctrl)
				tt.setupLdxMock(mockLdxClient)
				newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
					return mockLdxClient, nil
				}
			} else {
				// Default mock client for tests that don't need LDX mock setup
				mockLdxClient := ldx_mocks.NewMockClientWithResponsesInterface(ctrl)
				newClient = func(_ workflow.Engine, _ configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
					return mockLdxClient, nil
				}
			}

			if tt.setupApiMock != nil {
				mockApiClient := api_mocks.NewMockApiClient(ctrl)
				tt.setupApiMock(mockApiClient)
				newApiClient = func(_ workflow.Engine, _ configuration.Configuration) api.ApiClient {
					return mockApiClient
				}
			}

			result := GetUserConfigForProject(t.Context(), mockEngine, tt.dir, tt.orgId)

			if tt.expectNoError {
				assert.NoError(t, result.Error)
				if tt.expectedConfig {
					assert.NotNil(t, result.Config)
					assert.NotEmpty(t, result.RemoteUrl)
					assert.NotEmpty(t, result.ProjectRoot)
					// Verify response priority if expectedOrgId is set
					if tt.expectedOrgId != "" && result.Config != nil && result.Config.Data.Attributes.Organizations != nil {
						orgs := *result.Config.Data.Attributes.Organizations
						if len(orgs) > 0 {
							assert.Equal(t, tt.expectedOrgId, orgs[0].Id, "should use correct response type based on priority")
						}
					}
				}
			} else {
				assert.Error(t, result.Error)
				if tt.expectedError != "" {
					assert.Contains(t, result.Error.Error(), tt.expectedError)
				}
			}
		})
	}
}
