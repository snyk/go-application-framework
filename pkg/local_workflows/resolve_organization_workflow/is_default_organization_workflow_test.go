package resolve_organization_workflow

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api"
	api_mocks "github.com/snyk/go-application-framework/internal/mocks"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_InitIsDefaultOrganizationWorkflow_RegistersWorkflow(t *testing.T) {
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().
		Register(WORKFLOWID_IS_DEFAULT_ORGANIZATION, gomock.Any(), gomock.Any()).
		Return(nil, nil)

	err := InitIsDefaultOrganizationWorkflow(mockEngine)
	require.NoError(t, err)
}

func Test_isDefaultOrganizationWorkflowEntryPointDI_NoInput(t *testing.T) {
	mockInvCtx := setupMockIsDefaultOrgContext(t)

	_, err := isDefaultOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no input provided")
}

func Test_isDefaultOrganizationWorkflowEntryPointDI_InvalidInputPayload(t *testing.T) {
	mockInvCtx := setupMockIsDefaultOrgContext(t)

	invalidInput := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_IS_DEFAULT_ORGANIZATION, "invalid"),
		"application/go-struct",
		"not a valid input",
	)

	_, err := isDefaultOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{invalidInput}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid input payload type")
}

func Test_isDefaultOrganizationWorkflowEntryPointDI_MissingEmptyStringIs(t *testing.T) {
	mockInvCtx := setupMockIsDefaultOrgContext(t)

	input := IsDefaultOrganizationInput{
		Organization: "my-org",
		// EmptyStringIs is not set
	}
	inputData := createIsDefaultWorkflowInputData(t, input)

	_, err := isDefaultOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{inputData}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EmptyStringIs must be specified")
}

func Test_isDefaultOrganizationWorkflowEntryPoint_Integration(t *testing.T) {
	tests := []struct {
		name                 string
		setupApiMock         func(mock *api_mocks.MockApiClient)
		organization         string
		emptyStringIs        EmptyStringBehavior
		expectedIsDefaultOrg bool
		expectUnknownSlug    bool
		expectedErr          error
	}{
		{
			name:                 "empty string with EmptyIsDefaultOrg returns true",
			setupApiMock:         func(mock *api_mocks.MockApiClient) {},
			organization:         "",
			emptyStringIs:        EmptyIsDefaultOrg,
			expectedIsDefaultOrg: true,
		},
		{
			name:                 "empty string with EmptyIsUnknownSlug returns IsUnknownSlug true",
			setupApiMock:         func(mock *api_mocks.MockApiClient) {},
			organization:         "",
			emptyStringIs:        EmptyIsUnknownSlug,
			expectedIsDefaultOrg: false,
			expectUnknownSlug:    true,
		},
		{
			name:          "empty string with EmptyIsError returns error",
			setupApiMock:  func(mock *api_mocks.MockApiClient) {},
			organization:  "",
			emptyStringIs: EmptyIsError,
			expectedErr:   errors.New("organization not specified"),
		},
		{
			name: "UUID organization ID is default",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetDefaultOrgId().Return("123e4567-e89b-12d3-a456-426614174000", nil)
			},
			organization:         "123e4567-e89b-12d3-a456-426614174000",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: true,
		},
		{
			name: "UUID organization ID is not default",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetDefaultOrgId().Return("123e4567-e89b-12d3-a456-426614174000", nil)
			},
			organization:         "987e6543-e89b-12d3-a456-426614174999",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: false,
		},
		{
			name: "slug resolves to default org",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetOrgIdFromSlug("my-default-org").Return("123e4567-e89b-12d3-a456-426614174000", nil)
				mock.EXPECT().GetDefaultOrgId().Return("123e4567-e89b-12d3-a456-426614174000", nil)
			},
			organization:         "my-default-org",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: true,
		},
		{
			name: "slug resolves to non-default org",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetOrgIdFromSlug("some-other-org").Return("987e6543-e89b-12d3-a456-426614174999", nil)
				mock.EXPECT().GetDefaultOrgId().Return("123e4567-e89b-12d3-a456-426614174000", nil)
			},
			organization:         "some-other-org",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: false,
		},
		{
			name: "unknown slug returns IsUnknownSlug true",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetOrgIdFromSlug("invalid-slug").Return("", &api.OrgSlugNotFoundError{Slug: "invalid-slug"})
			},
			organization:         "invalid-slug",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: false,
			expectUnknownSlug:    true,
		},
		{
			name: "API error when getting default org with UUID",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetDefaultOrgId().Return("", errors.New("api error"))
			},
			organization:         "123e4567-e89b-12d3-a456-426614174000",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: false,
			expectedErr:          errors.New("failed to get default organization"),
		},
		{
			name: "API error when getting default org with slug",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetOrgIdFromSlug("my-org").Return("123e4567-e89b-12d3-a456-426614174000", nil)
				mock.EXPECT().GetDefaultOrgId().Return("", errors.New("api error"))
			},
			organization:         "my-org",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: false,
			expectedErr:          errors.New("failed to get default organization"),
		},
		{
			name: "empty default org ID from API",
			setupApiMock: func(mock *api_mocks.MockApiClient) {
				mock.EXPECT().GetDefaultOrgId().Return("", nil)
			},
			organization:         "123e4567-e89b-12d3-a456-426614174000",
			emptyStringIs:        EmptyIsError, // Not used but required
			expectedIsDefaultOrg: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)

			// Setup mocks
			mockApiClient := api_mocks.NewMockApiClient(ctrl)
			if tt.setupApiMock != nil {
				tt.setupApiMock(mockApiClient)
			}

			// Setup workflow context
			mockInvCtx := setupMockIsDefaultOrgContext(t)

			// Create input
			input := IsDefaultOrganizationInput{
				Organization:  tt.organization,
				EmptyStringIs: tt.emptyStringIs,
			}
			inputData := createIsDefaultWorkflowInputData(t, input)

			// Invoke the workflow
			output, err := isDefaultOrganizationWorkflowEntryPointDI(mockInvCtx, []workflow.Data{inputData}, mockApiClient)

			// Verify error expectations
			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr.Error())
				return
			}

			// Verify success
			require.NoError(t, err)
			require.Len(t, output, 1)

			// Parse output
			result, ok := output[0].GetPayload().(IsDefaultOrganizationOutput)
			require.True(t, ok, "output payload should be IsDefaultOrganizationOutput")

			// Verify result
			assert.Equal(t, tt.expectedIsDefaultOrg, result.IsDefaultOrg)
			assert.Equal(t, tt.expectUnknownSlug, result.IsUnknownSlug)
		})
	}
}

// Helper functions

func setupMockIsDefaultOrgContext(t *testing.T) *mocks.MockInvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger := zerolog.Logger{}

	mockInvCtx := mocks.NewMockInvocationContext(ctrl)
	mockInvCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	return mockInvCtx
}

func createIsDefaultWorkflowInputData(t *testing.T, input IsDefaultOrganizationInput) workflow.Data {
	t.Helper()
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_IS_DEFAULT_ORGANIZATION, "is-default-org-input"),
		"application/go-struct",
		input,
	)
}
