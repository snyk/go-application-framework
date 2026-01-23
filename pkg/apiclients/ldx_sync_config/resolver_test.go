package ldx_sync_config

import (
	"errors"
	"fmt"
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
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
			},
		},
		{
			name:          "no organizations in response, fallback to API",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult: LdxSyncConfigResult{
				Config:      makeUserConfigResponse([]v20241015.Organization{}),
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: tempDir,
			},
		},
		{
			name:          "nil organizations in response, fallback to API",
			setupApiMock:  func(mock *api_mocks.MockApiClient) { mock.EXPECT().GetDefaultOrgId().Return("default-org", nil) },
			expectedOrgId: "default-org",
			cfgResult: LdxSyncConfigResult{
				Config:      &v20241015.UserConfigResponse{},
				RemoteUrl:   "https://github.com/test/repo.git",
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
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
				ProjectRoot: tempDir,
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
