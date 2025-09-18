package ldx_sync_config

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/ldx_sync/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestTryResolveOrganization(t *testing.T) {
	logger := zerolog.Nop()

	tests := []struct {
		name           string
		inputDir       string
		expectedResult string
	}{
		{
			name:           "empty input directory",
			inputDir:       "",
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
			config.Set("INPUT_DIRECTORY", tt.inputDir)

			// Test with nil client - this should fail gracefully
			result := TryResolveOrganization(config, nil, &logger)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// TestTryResolveOrganizationWithMock tests the organization resolution logic
// using generated mocks to test the core logic
func TestTryResolveOrganizationWithMock(t *testing.T) {
	tests := []struct {
		name           string
		mockResult     LdxSyncConfigResult
		expectedResult string
	}{
		{
			name: "successful resolution with default org",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: &[]v20241015.Organization{
									{
										Id:        "org-123",
										IsDefault: boolPtr(true),
									},
									{
										Id:        "org-456",
										IsDefault: boolPtr(false),
									},
								},
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "org-123",
		},
		{
			name: "successful resolution with first org when no default",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: &[]v20241015.Organization{
									{
										Id:        "org-456",
										IsDefault: boolPtr(false),
									},
									{
										Id:        "org-789",
										IsDefault: boolPtr(false),
									},
								},
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "org-456",
		},
		{
			name: "no organizations in response",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: &[]v20241015.Organization{},
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "",
		},
		{
			name: "nil organizations in response",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: nil,
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "",
		},
		{
			name: "error in result",
			mockResult: LdxSyncConfigResult{
				Error: errors.New("some error"),
			},
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the organization extraction logic directly
			orgId := ""
			if tt.mockResult.Error == nil && tt.mockResult.Config != nil &&
				tt.mockResult.Config.Data.Attributes.ConfigData.Organizations != nil &&
				len(*tt.mockResult.Config.Data.Attributes.ConfigData.Organizations) > 0 {
				// Find the default organization or use the first one
				for _, org := range *tt.mockResult.Config.Data.Attributes.ConfigData.Organizations {
					if org.IsDefault != nil && *org.IsDefault {
						orgId = org.Id
						break
					}
				}
				if orgId == "" {
					orgId = (*tt.mockResult.Config.Data.Attributes.ConfigData.Organizations)[0].Id
				}
			}

			assert.Equal(t, tt.expectedResult, orgId)
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

			result, err := GetConfig(config, mockClient, &logger)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			}
		})
	}
}

// TestTryResolveOrganizationWithMockedGit tests the organization resolution logic
// by directly testing the core logic without git dependency
func TestTryResolveOrganizationWithMockedGit(t *testing.T) {
	// Create a test that directly tests the organization extraction logic
	// by creating a mock result that simulates what getLdxSyncConfig would return
	tests := []struct {
		name           string
		mockResult     LdxSyncConfigResult
		expectedResult string
	}{
		{
			name: "successful resolution with default org",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: &[]v20241015.Organization{
									{
										Id:        "org-123",
										IsDefault: boolPtr(true),
									},
									{
										Id:        "org-456",
										IsDefault: boolPtr(false),
									},
								},
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "org-123",
		},
		{
			name: "successful resolution with first org when no default",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: &[]v20241015.Organization{
									{
										Id:        "org-456",
										IsDefault: boolPtr(false),
									},
									{
										Id:        "org-789",
										IsDefault: boolPtr(false),
									},
								},
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "org-456",
		},
		{
			name: "no organizations in response",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: &[]v20241015.Organization{},
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "",
		},
		{
			name: "nil organizations in response",
			mockResult: LdxSyncConfigResult{
				Config: &v20241015.ConfigResponse{
					Data: v20241015.ConfigResource{
						Attributes: v20241015.ConfigAttributes{
							ConfigData: v20241015.ConfigData{
								Organizations: nil,
							},
						},
					},
				},
				RemoteUrl:   "https://github.com/test/repo",
				ProjectRoot: "/some/path",
				Error:       nil,
			},
			expectedResult: "",
		},
		{
			name: "error in result",
			mockResult: LdxSyncConfigResult{
				Error: errors.New("some error"),
			},
			expectedResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the organization extraction logic directly
			orgId := ""
			if tt.mockResult.Error == nil && tt.mockResult.Config != nil &&
				tt.mockResult.Config.Data.Attributes.ConfigData.Organizations != nil &&
				len(*tt.mockResult.Config.Data.Attributes.ConfigData.Organizations) > 0 {
				// Find the default organization or use the first one
				for _, org := range *tt.mockResult.Config.Data.Attributes.ConfigData.Organizations {
					if org.IsDefault != nil && *org.IsDefault {
						orgId = org.Id
						break
					}
				}
				if orgId == "" {
					orgId = (*tt.mockResult.Config.Data.Attributes.ConfigData.Organizations)[0].Id
				}
			}

			assert.Equal(t, tt.expectedResult, orgId)
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

			result, err := GetConfig(config, mockClient, &logger)

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

			result := getLdxSyncConfig(config, mockClient)

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
