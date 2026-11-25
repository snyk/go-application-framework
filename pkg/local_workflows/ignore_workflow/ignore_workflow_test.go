package ignore_workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api/contract"
	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	policyResponseJSON = `{
	"data": {
		"type": "policy",
		"id": "12345678-1234-1234-1234-123456789012",
		"attributes": {
			"name": "Test Policy",
			"created_at": "2024-01-01T00:00:00Z",
			"updated_at": "2024-01-01T00:00:00Z"
		}
	}
}`
	testRepoUrl    = "https://github.com/snyk/snyk-goof"
	testBranchName = "main"
	expectedUser   = "user@domain.com"
)

// Setup mock context for testing
func setupMockIgnoreContext(t *testing.T, payload string, statusCode int) *mocks.MockInvocationContext {
	t.Helper()
	logger := zerolog.Logger{}
	return setupMockIgnoreContextWithLogger(t, payload, statusCode, &logger)
}

func setupMockIgnoreContextWithLogger(t *testing.T, payload string, statusCode int, logger *zerolog.Logger) *mocks.MockInvocationContext {
	t.Helper()

	// setup
	config := configuration.New()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.ORGANIZATION, uuid.New().String())

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	mockUserInterface := mocks.NewMockUserInterface(ctrl)
	mockEngine := mocks.NewMockEngine(ctrl)

	mockUserInterface.EXPECT().Output(gomock.Any()).Return(nil).AnyTimes()
	mockUserInterface.EXPECT().Input(gomock.Any()).Return("", nil).AnyTimes()

	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: statusCode,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBufferString(payload)),
			// Must be set to non-nil value or it panics
			Header: http.Header{
				"Content-Type": []string{"application/vnd.api+json"},
			},
		}
	})
	// setup invocation context
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	invocationContextMock.EXPECT().GetUserInterface().Return(mockUserInterface).AnyTimes()
	invocationContextMock.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier(ignoreCreateWorkflowName)).AnyTimes()
	invocationContextMock.EXPECT().Context().Return(t.Context()).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
	mockData := []workflow.Data{workflow.NewData(
		workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "whoami"),
		"text/plain",
		expectedUser,
		workflow.WithLogger(logger),
	)}
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return(mockData, nil).AnyTimes()

	return invocationContextMock
}

func Test_getIgnoreRequestDetailsStructure(t *testing.T) {
	expireDate := "2025-01-01"
	userName := "test-user"
	ignoreType := "wont-fix"
	reason := "Test reason"
	orgName := "test-org"
	result := getIgnoreRequestDetailsStructure(expireDate, userName, orgName, ignoreType, reason)

	assert.Contains(t, result, "2025-01-01")
	assert.Contains(t, result, userName)
	assert.Contains(t, result, ignoreType)
	assert.Contains(t, result, orgName)
	assert.Contains(t, result, reason)
}

func Test_validIgnoreType(t *testing.T) {
	validTypes := []string{
		string(policyApi.TemporaryIgnore),
		string(policyApi.WontFix),
		string(policyApi.NotVulnerable),
	}

	for _, validType := range validTypes {
		t.Run("valid: "+validType, func(t *testing.T) {
			err := isValidIgnoreType(validType)
			assert.Nil(t, err, "Should be a valid ignore type")
		})
	}

	invalidTypes := []string{
		"invalid",
		"",
		"permanently-ignore",
	}

	for _, invalidType := range invalidTypes {
		t.Run("invalid: "+invalidType, func(t *testing.T) {
			err := isValidIgnoreType(invalidType)
			assert.NotNil(t, err, "Should be an invalid ignore type")
		})
	}
}

func Test_createPolicy(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		invocationContext := setupMockIgnoreContext(t, policyResponseJSON, http.StatusCreated)

		var input policyApi.CreatePolicyPayload
		input.Data.Type = policyApi.CreatePolicyPayloadDataTypePolicy
		orgId := uuid.New()
		result, err := sendCreateIgnore(invocationContext, input, orgId)

		assert.NoError(t, err, "Should not return an error")
		assert.NotNil(t, result, "Should return a policy response")
		expectedUuid, err := uuid.Parse("12345678-1234-1234-1234-123456789012")
		assert.NoError(t, err)
		assert.Equal(t, expectedUuid, result.Id, "Should have the correct ID")
	})

	t.Run("server error", func(t *testing.T) {
		invocationContext := setupMockIgnoreContext(t, "Internal Server Error", http.StatusInternalServerError)

		var input policyApi.CreatePolicyPayload
		input.Data.Type = policyApi.CreatePolicyPayloadDataTypePolicy

		orgId := uuid.New()
		_, err := sendCreateIgnore(invocationContext, input, orgId)

		assert.Error(t, err, "Should return an error")
		assert.Contains(t, err.Error(), "500", "Should contain status code")
	})
}

func Test_createPayload(t *testing.T) {
	expireDate, err := time.Parse(time.DateOnly, "2025-01-01")
	assert.NoError(t, err)
	ignoreType := string(policyApi.TemporaryIgnore)
	reason := "Test reason"
	findingsId := uuid.New().String()

	payload := createPayload(testRepoUrl, testBranchName, &expireDate, ignoreType, reason, findingsId)

	assert.Equal(t, policyApi.CreatePolicyPayloadDataTypePolicy, payload.Data.Type, "Should have correct payload type")
	assert.Equal(t, ignoreType, string(payload.Data.Attributes.Action.Data.IgnoreType), "Should have correct ignore type")
	assert.Equal(t, reason, *payload.Data.Attributes.Action.Data.Reason, "Should have correct reason")
	assert.NotEmpty(t, payload.Data.Attributes.ConditionsGroup.Conditions, "Should have condition")
	assert.Equal(t, policyApi.PolicyCreateSnykAssetFindingV1, payload.Data.Attributes.ConditionsGroup.Conditions[0].Field, "Should have correct findings ID")
	assert.Equal(t, policyApi.PolicyCreateIncludes, payload.Data.Attributes.ConditionsGroup.Conditions[0].Operator, "Condition operation must be include")
	assert.Equal(t, findingsId, payload.Data.Attributes.ConditionsGroup.Conditions[0].Value, "Should have correct findings ID")
	assert.Equal(t, expireDate, *payload.Data.Attributes.Action.Data.Expires, "Should have correct expiration date")
}

func Test_ignoreCreateWorkflowEntryPoint(t *testing.T) {
	t.Run("non-interactive mode success", func(t *testing.T) {
		expectedFindingsId := uuid.New().String()
		expectedIgnoreType := string(policyApi.TemporaryIgnore)
		expectedReason := "Test reason"
		policyId := uuid.New().String()
		expectedExpirationDate := time.Date(2025, 12, 12, 0, 0, 0, 0, time.UTC)
		responseMock := fmt.Sprintf(`{
	  "data": {
    "id": "%s",
    "type": "policy",
    "attributes": {
      "action": {
        "data": {
          "expires": "%s",
          "ignore_type": "%s",
          "reason": "%s"
        }
      },
      "action_type": "%s",
      "conditions_group": {
        "conditions": [
          {
            "field": "%s",
            "operator": "%s",
            "value": "%s"
          }
        ],
        "logical_operator": "%s"
      },
      "created_by": {
        "email": "%s"
      },
      "review": "%s"
    }
}
}`, policyId, expectedExpirationDate.Format(time.RFC3339), expectedIgnoreType, expectedReason, policyApi.PolicyAttributesActionTypeIgnore, policyApi.Snykassetfindingv1, policyApi.Includes, expectedFindingsId, policyApi.And, expectedUser, policyApi.PolicyReviewPending)
		invocationContext := setupMockIgnoreContext(t, responseMock, http.StatusCreated)
		config := invocationContext.GetConfiguration()
		config.Set(InteractiveKey, false)

		config.Set(FindingsIdKey, expectedFindingsId)
		config.Set(IgnoreTypeKey, expectedIgnoreType)
		config.Set(ReasonKey, expectedReason)
		config.Set(ExpirationKey, expectedExpirationDate.Format(time.DateOnly))
		config.Set(RemoteRepoUrlKey, testRepoUrl)
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(EnrichResponseKey, true)

		result, err := ignoreCreateWorkflowEntryPoint(invocationContext, nil)
		assert.NoError(t, err, "Should not return an error")
		assert.Greater(t, len(result), 0, "Should return result data")
		payload := result[0].GetPayload()
		assert.NotNil(t, payload, "payload should not be nil")

		var policyResp sarif.Suppression
		data, ok := payload.([]byte)
		assert.True(t, ok)
		err = json.Unmarshal(data, &policyResp)
		assert.NoError(t, err, "Should parse JSON response")
		assert.Equal(t, policyId, policyResp.Guid)
		assert.Equal(t, expectedUser, *policyResp.Properties.IgnoredBy.Email)
		assert.Equal(t, sarif.UnderReview, policyResp.Status)
		assert.Equal(t, expectedExpirationDate.Format(time.RFC3339), *policyResp.Properties.Expiration)
		assert.Equal(t, expectedReason, policyResp.Justification)
	})
	t.Run("non-interactive mode success no expiration", func(t *testing.T) {
		expectedFindingsId := uuid.New().String()
		expectedIgnoreType := string(policyApi.WontFix)
		expectedReason := "Test reason"
		policyId := uuid.New().String()
		responseMock := fmt.Sprintf(`{
	  "data": {
    "id": "%s",
    "type": "policy",
    "attributes": {
      "action": {
        "data": {
          "ignore_type": "%s",
          "reason": "%s"
        }
      },
      "action_type": "%s",
      "conditions_group": {
        "conditions": [
          {
            "field": "%s",
            "operator": "%s",
            "value": "%s"
          }
        ],
        "logical_operator": "%s"
      },
      "created_by": {
        "email": "%s"
      },
      "review": "%s"
    }
}
}`, policyId, expectedIgnoreType, expectedReason, policyApi.PolicyAttributesActionTypeIgnore, policyApi.Snykassetfindingv1, policyApi.Includes, expectedFindingsId, policyApi.And, expectedUser, policyApi.PolicyReviewPending)
		invocationContext := setupMockIgnoreContext(t, responseMock, http.StatusCreated)
		config := invocationContext.GetConfiguration()
		config.Set(InteractiveKey, false)

		config.Set(FindingsIdKey, expectedFindingsId)
		config.Set(IgnoreTypeKey, expectedIgnoreType)
		config.Set(ReasonKey, expectedReason)
		config.Set(RemoteRepoUrlKey, testRepoUrl)
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(EnrichResponseKey, true)

		result, err := ignoreCreateWorkflowEntryPoint(invocationContext, nil)
		assert.Error(t, err, "Should return an error")
		assert.Nil(t, result, "payload be nil")
	})

	t.Run("non-interactive mode missing expiration returns empty flag error", func(t *testing.T) {
		expectedFindingsId := uuid.New().String()
		expectedIgnoreType := string(policyApi.WontFix)
		expectedReason := "Test reason"

		invocationContext := setupMockIgnoreContext(t, "{}", http.StatusCreated)
		config := invocationContext.GetConfiguration()
		config.Set(InteractiveKey, false)

		config.Set(FindingsIdKey, expectedFindingsId)
		config.Set(IgnoreTypeKey, expectedIgnoreType)
		config.Set(ReasonKey, expectedReason)
		config.Set(RemoteRepoUrlKey, testRepoUrl)
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(EnrichResponseKey, true)

		result, err := ignoreCreateWorkflowEntryPoint(invocationContext, nil)
		assert.Nil(t, result, "result should be nil when the expiration is missing")
		snykErr := snyk_errors.Error{}
		assert.True(t, errors.As(err, &snykErr))
		assert.Equal(t, "The expiration flag is required and cannot be empty. Provide it using the --expiration flag. The date format is YYYY-MM-DD or 'never' for no expiration.", snykErr.Detail)
	})

	t.Run("logs the branch name error when the branch cannot be read", func(t *testing.T) {
		policyId := uuid.New().String()
		findingId := uuid.New().String()
		ignoreType := string(policyApi.WontFix)
		reason := "Test reason"
		responseMock := getSuccessfulPolicyResponse(policyId, findingId, ignoreType, reason, expectedUser, nil)

		// not a git repository, so the branch name cannot be determined
		inputDir := t.TempDir()
		_, expectedBranchNameErr := git.BranchNameFromDir(inputDir)
		assert.Error(t, expectedBranchNameErr)

		var logOutput bytes.Buffer
		logger := zerolog.New(&logOutput)
		invocationContext := setupMockIgnoreContextWithLogger(t, responseMock, http.StatusCreated, &logger)
		config := invocationContext.GetConfiguration()
		config.Set(InteractiveKey, false)
		config.Set(configuration.INPUT_DIRECTORY, inputDir)
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(ExpirationKey, local_models.DefaultSuppressionExpiration)
		config.Set(RemoteRepoUrlKey, testRepoUrl)

		_, err := ignoreCreateWorkflowEntryPoint(invocationContext, nil)
		assert.NoError(t, err)
		assert.Contains(t, logOutput.String(), expectedBranchNameErr.Error())
	})
}

func setupInteractiveMockContext(t *testing.T, mockApiResponse string, mockApiStatusCode int) (*mocks.MockInvocationContext, *mocks.MockUserInterface) {
	t.Helper()

	logger := zerolog.Logger{}
	config := configuration.New()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.ORGANIZATION, uuid.New().String())
	config.Set(ConfigIgnoreApprovalEnabled, true)
	config.Set(InteractiveKey, true) // Always interactive
	config.Set(EnrichResponseKey, true)
	config.Set(configuration.ORGANIZATION_SLUG, "some-org")
	tempDir := t.TempDir()
	config.Set(configuration.INPUT_DIRECTORY, tempDir) // no inferred remote url

	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	mockUserInterface := mocks.NewMockUserInterface(ctrl)
	mockEngine := mocks.NewMockEngine(ctrl)

	mockUserInterface.EXPECT().Output(gomock.Any()).Return(nil).AnyTimes()

	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: mockApiStatusCode,
			Body:       io.NopCloser(bytes.NewBufferString(mockApiResponse)),
			Header:     http.Header{"Content-Type": []string{"application/vnd.api+json"}},
		}
	})

	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	invocationContextMock.EXPECT().GetUserInterface().Return(mockUserInterface).AnyTimes()
	invocationContextMock.EXPECT().GetWorkflowIdentifier().Return(WORKFLOWID_IGNORE_CREATE).AnyTimes()
	invocationContextMock.EXPECT().Context().Return(t.Context()).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()

	mockWhoamiData := []workflow.Data{workflow.NewData(
		workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "whoami"),
		"text/plain",
		expectedUser,
		workflow.WithLogger(&logger),
	)}
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).Return(mockWhoamiData, nil).AnyTimes()

	return invocationContextMock, mockUserInterface
}

func Test_InteractiveIgnoreWorkflow(t *testing.T) {
	policyId := uuid.New()
	email := "test@email.com"
	findingId := "11111111-1111-1111-1111-111111111111"
	ignoreType := string(policyApi.TemporaryIgnore)
	reason := "Test interactive reason"
	repoUrl := "https://github.com/example/test-repo"
	expiration := "2025-12-31"
	expirationDate, err := time.Parse(time.DateOnly, expiration)
	assert.NoError(t, err)

	t.Run("all flags provided, no prompts expected", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, expiration)

		mockUI.EXPECT().Input(gomock.Any()).Times(0)

		result, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)
		assert.Greater(t, len(result), 0, "Should return result data")

		var policyResp sarif.Suppression
		data, ok := result[0].GetPayload().([]byte)
		assert.True(t, ok)
		err = json.Unmarshal(data, &policyResp)
		assert.NoError(t, err, "Should parse JSON response")
		assert.Equal(t, policyId.String(), policyResp.Guid)
		assert.Equal(t, email, *policyResp.Properties.IgnoredBy.Email)
		assert.Equal(t, sarif.UnderReview, policyResp.Status)
		assert.Equal(t, expirationDate.Format(time.RFC3339), *policyResp.Properties.Expiration)
	})

	t.Run("finding-id not provided, prompts for finding-id", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, nil)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, expiration)

		mockUI.EXPECT().Input(gomock.Eq(findingsIdDescription)).Return(findingId, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)
	})

	t.Run("ignore-type not provided, prompts for ignore-type", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, nil)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(ReasonKey, reason)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, local_models.DefaultSuppressionExpiration)

		mockUI.EXPECT().Input(gomock.Eq(ignoreTypeDescription)).Return(ignoreType, nil).Times(1)

		result, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)

		var policyResp sarif.Suppression
		data, ok := result[0].GetPayload().([]byte)
		assert.True(t, ok)
		err = json.Unmarshal(data, &policyResp)
		assert.NoError(t, err, "Should parse JSON response")
		assert.Equal(t, policyId.String(), policyResp.Guid)
		assert.Equal(t, ignoreType, string(policyResp.Properties.Category))
	})

	t.Run("reason not provided, prompts for reason", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, nil)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, local_models.DefaultSuppressionExpiration)

		mockUI.EXPECT().Input(gomock.Eq(reasonDescription)).Return(reason, nil).Times(1)

		result, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)

		var policyResp sarif.Suppression
		data, ok := result[0].GetPayload().([]byte)
		assert.True(t, ok)
		err = json.Unmarshal(data, &policyResp)
		assert.NoError(t, err, "Should parse JSON response")
		assert.Equal(t, policyId.String(), policyResp.Guid)
		assert.Equal(t, reason, policyResp.Justification)
	})

	t.Run("remote-repo-url not provided, prompts for remote-repo-url", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(ExpirationKey, expiration)

		mockUI.EXPECT().Input(gomock.Eq(remoteRepoUrlDescription)).Return(repoUrl, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)
	})

	t.Run("prompt for ignore-type and reason", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, expiration)

		mockUI.EXPECT().Input(gomock.Eq(ignoreTypeDescription)).Return(ignoreType, nil).Times(1)

		expectedReasonPrompt := reasonDescription
		mockUI.EXPECT().Input(gomock.Eq(expectedReasonPrompt)).Return(reason, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)
	})

	t.Run("prompt for expiration", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(RemoteRepoUrlKey, repoUrl)

		mockUI.EXPECT().Input(gomock.Eq(expirationDescription)).Return(expiration, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)
	})

	t.Run("prompt for expiration - never expiry", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(RemoteRepoUrlKey, repoUrl)

		mockUI.EXPECT().Input(gomock.Eq(expirationDescription)).Return("", nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.NoError(t, err)
	})

	t.Run("prompt for expiration - invalid value", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(IgnoreTypeKey, ignoreType)
		config.Set(ReasonKey, reason)
		config.Set(RemoteRepoUrlKey, repoUrl)

		mockUI.EXPECT().Input(gomock.Eq(expirationDescription)).Return("invalid-date", nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.Error(t, err, "Expected to have an error regarding invalid expiration date")
		snykErr := snyk_errors.Error{}
		assert.True(t, errors.As(err, &snykErr))
		assert.Equal(t, snykErr.ErrorCode, "SNYK-CLI-0010")
	})

	t.Run("prompt for ignore-type - invalid value", func(t *testing.T) {
		mockResponse := getSuccessfulPolicyResponse(policyId.String(), findingId, ignoreType, reason, email, &expirationDate)
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusCreated)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, expiration)

		mockUI.EXPECT().Input(gomock.Eq(ignoreTypeDescription)).Return("I'm not a valid ignore type", nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.Error(t, err, "Expected to have an error regarding invalid ignore type")
		snykErr := snyk_errors.Error{}
		assert.True(t, errors.As(err, &snykErr))
		assert.Equal(t, snykErr.ErrorCode, "SNYK-CLI-0010")
	})

	t.Run("prompt for ignore-type - bad request error", func(t *testing.T) {
		mockResponse := get400PolicyResponse()
		invocationCtx, mockUI := setupInteractiveMockContext(t, mockResponse, http.StatusInternalServerError)
		config := invocationCtx.GetConfiguration()
		config.Set(FindingsIdKey, findingId)
		config.Set(RemoteRepoUrlKey, repoUrl)
		config.Set(ExpirationKey, expiration)

		expectedIgnoreTypePrompt := ignoreTypeDescription
		mockUI.EXPECT().Input(gomock.Eq(expectedIgnoreTypePrompt)).Return("I'm not a valid ignore type", nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(invocationCtx, nil)
		assert.Error(t, err, "Expected to have an error regarding invalid ignore type")
	})
}

func getSuccessfulPolicyResponse(policyIdStr, findingId, ignoreTypeStr, reasonStr, userEmailStr string, expiration *time.Time) string {
	policyUUID, err := uuid.Parse(policyIdStr)
	if err != nil {
		panic(err)
	}
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	policyName := "Generated Policy"
	createdByName := "Test User"

	response := &policyApi.CreateOrgPolicyResponse{
		ApplicationvndApiJSON201: &struct {
			Data    policyApi.PolicyResponse `json:"data"`
			Jsonapi policyApi.JsonApi        `json:"jsonapi"`
			Links   *policyApi.SelfLink      `json:"links,omitempty"`
		}{
			Data: policyApi.PolicyResponse{
				Id:   policyUUID,
				Type: policyApi.PolicyResponseTypePolicy,
				Attributes: policyApi.PolicyResponseAttributes{
					Name:      policyName,
					CreatedAt: fixedTime,
					UpdatedAt: fixedTime,
					Action: policyApi.PolicyActionIgnore{
						Data: policyApi.PolicyActionIgnoreData{
							Expires:    expiration,
							IgnoreType: policyApi.PolicyActionIgnoreDataIgnoreType(ignoreTypeStr),
							Reason:     &reasonStr,
						},
					},
					ActionType: policyApi.Ignore,
					ConditionsGroup: policyApi.PolicyResponseConditionsGroup{
						Conditions: []policyApi.PolicyResponseCondition{
							{
								Field:    policyApi.PolicyResponseSnykAssetFindingV1,
								Operator: policyApi.PolicyResponseIncludes,
								Value:    findingId,
							},
						},
						LogicalOperator: policyApi.PolicyResponseAnd,
					},
					CreatedBy: &policyApi.Principal{
						Name:  createdByName,
						Email: &userEmailStr,
					},
					Review: policyApi.PolicyReviewPending,
				},
			},
			Jsonapi: policyApi.JsonApi{Version: "1.0"},
		},
	}
	strResponse, err := json.Marshal(response.ApplicationvndApiJSON201)
	if err != nil {
		panic(err)
	}
	return string(strResponse)
}

func get400PolicyResponse() string {
	id := uuid.New()
	code := "BAD_REQ"
	title := "Bad Request"
	response := &policyApi.CreateOrgPolicyResponse{
		ApplicationvndApiJSON400: &policyApi.N400{
			Jsonapi: policyApi.JsonApi{Version: "1.0"},
			Errors: []policyApi.Error{
				{
					Id:     &id,
					Status: "400",
					Code:   &code,
					Title:  &title,
					Detail: "Invalid input provided.",
				},
			},
		},
	}
	strResponse, err := json.Marshal(response.ApplicationvndApiJSON400)
	if err != nil {
		panic(err)
	}
	return string(strResponse)
}

func Test_getExpireValue(t *testing.T) {
	t.Run("valid date format", func(t *testing.T) {
		dateStr := "2025-12-31"
		expectedTime, err := time.Parse(time.DateOnly, dateStr)
		assert.NoError(t, err)
		result, err := getExpireValue(dateStr)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedTime, *result)
	})

	t.Run("invalid date format", func(t *testing.T) {
		dateStr := "31-12-2025"
		result, err := getExpireValue(dateStr)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("'never' value", func(t *testing.T) {
		dateStr := local_models.DefaultSuppressionExpiration
		result, err := getExpireValue(dateStr)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty string", func(t *testing.T) {
		dateStr := ""
		result, err := getExpireValue(dateStr)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("other invalid value", func(t *testing.T) {
		dateStr := "invalid"
		result, err := getExpireValue(dateStr)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func Test_getOrgIgnoreApprovalEnabled(t *testing.T) {
	t.Run("returns existing value when not nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockEngine := mocks.NewMockEngine(ctrl)
		mockConfig := mocks.NewMockConfiguration(ctrl)

		// Expect the calls made during getOrgIgnoreApprovalEnabled function creation
		mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
		mockConfig.EXPECT().AddKeyDependency(ConfigIgnoreApprovalEnabled, configuration.ORGANIZATION).Return(nil)

		defaultValueFunc := getOrgIgnoreApprovalEnabled(mockEngine)

		result, err := defaultValueFunc(nil, true)
		assert.NoError(t, err)
		assert.Equal(t, true, result)

		result, err = defaultValueFunc(nil, false)
		assert.NoError(t, err)
		assert.Equal(t, false, result)
	})

	t.Run("approval workflow enabled", func(t *testing.T) {
		result, err := setupMockEngineForOrgSettings(t, &contract.OrgSettingsResponse{
			Ignores: &contract.OrgIgnoreSettings{ApprovalWorkflowEnabled: true},
		})

		assert.NoError(t, err)
		assert.Equal(t, true, result)
	})

	t.Run("approval workflow disabled", func(t *testing.T) {
		result, err := setupMockEngineForOrgSettings(t, &contract.OrgSettingsResponse{
			Ignores: &contract.OrgIgnoreSettings{ApprovalWorkflowEnabled: false},
		})

		assert.NoError(t, err)
		assert.Equal(t, false, result)
	})

	t.Run("ignores field is nil", func(t *testing.T) {
		result, err := setupMockEngineForOrgSettings(t, &contract.OrgSettingsResponse{
			Ignores: nil,
		})

		assert.NoError(t, err)
		assert.Equal(t, false, result)
	})

	t.Run("API call fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		logger := zerolog.Logger{}
		orgId := uuid.New().String()
		apiUrl := "https://api.snyk.io"

		mockEngine := mocks.NewMockEngine(ctrl)
		mockConfig := mocks.NewMockConfiguration(ctrl)
		mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)

		httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString("Internal Server Error")),
			}
		})

		// Expect the calls made during getOrgIgnoreApprovalEnabled function creation
		mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
		mockConfig.EXPECT().AddKeyDependency(ConfigIgnoreApprovalEnabled, configuration.ORGANIZATION).Return(nil)

		// Expect the calls made during the actual default value function execution
		mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
		mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess)
		mockEngine.EXPECT().GetLogger().Return(&logger)
		mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return(orgId)
		mockConfig.EXPECT().GetString(configuration.API_URL).Return(apiUrl)
		mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient)

		defaultValueFunc := getOrgIgnoreApprovalEnabled(mockEngine)
		result, err := defaultValueFunc(mockConfig, nil)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "unable to retrieve org settings")
	})
}

func setupMockEngineForOrgSettings(t *testing.T, response *contract.OrgSettingsResponse) (interface{}, error) {
	t.Helper()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	orgId := uuid.New().String()
	apiUrl := "https://api.snyk.io"

	responseJSON, err := json.Marshal(response)
	assert.NoError(t, err)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockConfig := mocks.NewMockConfiguration(ctrl)
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)

	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
		}
	})

	// Expect the calls made during getOrgIgnoreApprovalEnabled function creation
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
	mockConfig.EXPECT().AddKeyDependency(ConfigIgnoreApprovalEnabled, configuration.ORGANIZATION).Return(nil)

	// Expect the calls made during the actual default value function execution
	mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess)
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return(orgId)
	mockConfig.EXPECT().GetString(configuration.API_URL).Return(apiUrl)
	mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient)

	defaultValueFunc := getOrgIgnoreApprovalEnabled(mockEngine)
	return defaultValueFunc(mockConfig, nil)
}

const (
	testOpenSourceId           = "SNYK-JS-LODASH-567746"
	testOpenSourcePolicyId     = "22222222-2222-2222-2222-222222222222"
	testCleanRepoUrl           = "https://github.com/org/repo.git"
	testNormalizedRepoUrl      = "https://github.com/org/repo"
	testRepoUrlWithCredentials = "https://x-access-token:SECRET@github.com/org/repo.git"
	testReason                 = "Test reason"
	testExpiration             = "2027-03-31"
	testOrgSlug                = "some-org"
	invalidFindingIdMessage    = "--finding-id must be a Snyk Code finding ID (a UUID) or a Snyk Open Source issue ID (starting with SNYK-, snyk:lic: or npm:)."
	scopeLineOpenSource        = "\n👉🏼 This ignore applies to every branch and every project of the repository."
	scopeLineSnykCode          = "\n👉🏼 Ensure the code containing the issue is committed and pushed to remote origin, so approvers can review it."
	findingIdPromptOutput      = "<p class='prompt-help'>\nEnter the Finding ID of the issue you want to ignore.</p>"
	requestSentEvent           = "<request sent>"
)

// ignoreCreateRun records, in order, what a run of the ignore.create workflow prints and when it sends its requests.
type ignoreCreateRun struct {
	invocationCtx *mocks.MockInvocationContext
	userInterface *mocks.MockUserInterface
	config        configuration.Configuration
	events        []string
	requests      []string
	requestBodies []string
	whoamiCalls   int
}

// setupIgnoreCreateRun prepares a run in a clone whose origin is testCleanRepoUrl, with every flag but --finding-id and
// --remote-repo-url set, whose request is answered by a 201 with responseBody.
func setupIgnoreCreateRun(t *testing.T, interactive bool, responseBody string) *ignoreCreateRun {
	t.Helper()
	var run *ignoreCreateRun
	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		run.requests = append(run.requests, req.Method+" "+req.URL.String())
		run.requestBodies = append(run.requestBodies, string(body))
		run.events = append(run.events, requestSentEvent)
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
			Header:     http.Header{"Content-Type": []string{"application/vnd.api+json"}},
		}
	})
	run = newIgnoreCreateRun(t, interactive, "https://api.snyk.io", httpClient)
	return run
}

// setupIgnoreCreateRunWithServer prepares a non-interactive Open Source run whose request goes through the real networking
// stack, with errorHandler as its network error handler, to a server answering with statusCode, contentType and body.
func setupIgnoreCreateRunWithServer(t *testing.T, errorHandler networktypes.ErrorHandlerFunc, statusCode int, contentType string, body string) *ignoreCreateRun {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(statusCode)
		_, err := w.Write([]byte(body))
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	networkConfig := configuration.New()
	networkConfig.Set(configuration.API_URL, server.URL)
	network := networking.NewNetworkAccess(networkConfig)
	network.AddErrorHandler(errorHandler)

	run := newIgnoreCreateRun(t, false, server.URL, network.GetHttpClient())
	run.config.Set(FindingsIdKey, testOpenSourceId)
	return run
}

func newIgnoreCreateRun(t *testing.T, interactive bool, apiUrl string, httpClient *http.Client) *ignoreCreateRun {
	t.Helper()
	logger := zerolog.Nop()
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	mockEngine := mocks.NewMockEngine(ctrl)
	run := &ignoreCreateRun{
		invocationCtx: mocks.NewMockInvocationContext(ctrl),
		userInterface: mocks.NewMockUserInterface(ctrl),
		config:        configuration.New(),
	}

	run.config.Set(configuration.API_URL, apiUrl)
	run.config.Set(configuration.ORGANIZATION, uuid.New().String())
	run.config.Set(configuration.ORGANIZATION_SLUG, testOrgSlug)
	run.config.Set(configuration.INPUT_DIRECTORY, initRepoWithOrigin(t, testCleanRepoUrl))
	run.config.Set(InteractiveKey, interactive)
	run.config.Set(IgnoreTypeKey, string(policyApi.WontFix))
	run.config.Set(ReasonKey, testReason)
	run.config.Set(ExpirationKey, testExpiration)

	run.userInterface.EXPECT().Output(gomock.Any()).DoAndReturn(func(output string) error {
		run.events = append(run.events, output)
		return nil
	}).AnyTimes()

	whoamiData := []workflow.Data{workflow.NewData(
		workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "whoami"),
		"text/plain",
		expectedUser,
		workflow.WithLogger(&logger),
	)}
	mockEngine.EXPECT().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, gomock.Any()).DoAndReturn(func(workflow.Identifier, configuration.Configuration) ([]workflow.Data, error) {
		run.whoamiCalls++
		return whoamiData, nil
	}).AnyTimes()

	run.invocationCtx.EXPECT().GetConfiguration().Return(run.config).AnyTimes()
	run.invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	run.invocationCtx.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	run.invocationCtx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	run.invocationCtx.EXPECT().GetUserInterface().Return(run.userInterface).AnyTimes()
	run.invocationCtx.EXPECT().GetWorkflowIdentifier().Return(WORKFLOWID_IGNORE_CREATE).AnyTimes()
	run.invocationCtx.EXPECT().Context().Return(t.Context()).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()

	return run
}

// getOpenSourcePolicyResponse returns the body of a 201 for an Open Source ignore with the given review.
func getOpenSourcePolicyResponse(t *testing.T, review policyApi.PolicyReview) string {
	t.Helper()
	createdAt := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	reason := testReason
	body, err := json.Marshal(struct {
		Data    policyApi.PolicyResponse `json:"data"`
		Jsonapi policyApi.JsonApi        `json:"jsonapi"`
	}{
		Data: policyApi.PolicyResponse{
			Id:   uuid.MustParse(testOpenSourcePolicyId),
			Type: policyApi.PolicyResponseTypePolicy,
			Attributes: policyApi.PolicyResponseAttributes{
				Action: policyApi.PolicyActionIgnore{
					Data: policyApi.PolicyActionIgnoreData{IgnoreType: policyApi.WontFix, Reason: &reason},
				},
				ActionType: policyApi.Ignore,
				ConditionsGroup: policyApi.PolicyResponseConditionsGroup{
					Conditions: []policyApi.PolicyResponseCondition{
						{Field: policyApi.PolicyResponseSnykID, Operator: policyApi.PolicyResponseIncludes, Value: testOpenSourceId},
						{Field: policyApi.PolicyResponseAssetID, Operator: policyApi.PolicyResponseIncludes, Value: "33333333-3333-3333-3333-333333333333"},
					},
					LogicalOperator: policyApi.PolicyResponseAnd,
				},
				CreatedAt: createdAt,
				UpdatedAt: createdAt,
				Review:    review,
			},
		},
		Jsonapi: policyApi.JsonApi{Version: "1.0"},
	})
	require.NoError(t, err)
	return string(body)
}

// initRepoWithOrigin returns the directory of a new git repository whose origin remote has originUrl.
func initRepoWithOrigin(t *testing.T, originUrl string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{originUrl}})
	require.NoError(t, err)
	return dir
}

func Test_ignoreCreateWorkflowEntryPoint_productFromFindingId(t *testing.T) {
	codeId := uuid.New().String()
	testCases := []struct {
		name          string
		findingId     string
		expectedField policyApi.PolicyCreateConditionField // empty when the id is rejected
	}{
		{name: "UUID makes a Snyk Code ignore", findingId: codeId, expectedField: policyApi.PolicyCreateSnykAssetFindingV1},
		{name: "uppercase UUID makes a Snyk Code ignore", findingId: strings.ToUpper(codeId), expectedField: policyApi.PolicyCreateSnykAssetFindingV1},
		{name: "SNYK- id makes an Open Source ignore", findingId: "SNYK-JS-LODASH-567746", expectedField: policyApi.PolicyCreateSnykID},
		{name: "lowercase snyk- id makes an Open Source ignore", findingId: "snyk-js-lodash-567746", expectedField: policyApi.PolicyCreateSnykID},
		{name: "snyk:lic: id makes an Open Source ignore", findingId: "snyk:lic:npm:foo:MIT", expectedField: policyApi.PolicyCreateSnykID},
		{name: "uppercase SNYK:LIC: id makes an Open Source ignore", findingId: "SNYK:LIC:npm:foo:MIT", expectedField: policyApi.PolicyCreateSnykID},
		{name: "npm: id makes an Open Source ignore", findingId: "npm:adm-zip:20180415", expectedField: policyApi.PolicyCreateSnykID},
		{name: "uppercase NPM: id makes an Open Source ignore", findingId: "NPM:adm-zip:20180415", expectedField: policyApi.PolicyCreateSnykID},
		{name: "junk id is rejected", findingId: "junk"},
		{name: "empty id is rejected", findingId: ""},
		{name: "CVE id is rejected", findingId: "CVE-2021-23337"},
		{name: "snyk: id of another kind is rejected", findingId: "snyk:foo"},
	}

	for _, tc := range testCases {
		for _, interactive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s (interactive=%t)", tc.name, interactive), func(t *testing.T) {
				run := setupIgnoreCreateRun(t, interactive, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewPending))
				if interactive {
					run.userInterface.EXPECT().Input(findingsIdDescription).Return(tc.findingId, nil).Times(1)
				} else {
					run.config.Set(FindingsIdKey, tc.findingId)
				}

				_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

				if tc.expectedField == "" {
					var snykErr snyk_errors.Error
					require.ErrorAs(t, err, &snykErr)
					assert.Equal(t, "SNYK-CLI-0010", snykErr.ErrorCode)
					assert.Equal(t, invalidFindingIdMessage, snykErr.Detail)
					assert.Empty(t, run.requests, "an invalid id must send no request")
					assert.Zero(t, run.whoamiCalls, "an invalid id must not call whoami")
					return
				}
				require.NoError(t, err)
				require.Len(t, run.requestBodies, 1)
				var payload policyApi.CreatePolicyPayload
				require.NoError(t, json.Unmarshal([]byte(run.requestBodies[0]), &payload))
				assert.Equal(t, tc.expectedField, payload.Data.Attributes.ConditionsGroup.Conditions[0].Field)
				assert.Equal(t, tc.findingId, payload.Data.Attributes.ConditionsGroup.Conditions[0].Value)
			})
		}
	}
}

func Test_ignoreCreateWorkflowEntryPoint_request(t *testing.T) {
	codeId := uuid.New().String()
	testCases := []struct {
		name         string
		findingId    string
		expectedBody string
	}{
		{
			name:      "Snyk Code: one finding condition, repository and branch in meta, as before",
			findingId: codeId,
			expectedBody: fmt.Sprintf(`{"data": {
				"type": "policy",
				"meta": {"repo_url": "https://github.com/org/repo.git", "branch_name": ""},
				"attributes": {
					"name": "",
					"action_type": "ignore",
					"action": {"data": {"ignore_type": "wont-fix", "reason": "Test reason", "expires": "2027-03-31T00:00:00Z"}},
					"conditions_group": {
						"logical_operator": "and",
						"conditions": [{"field": "snyk/asset/finding/v1", "operator": "includes", "value": "%s"}]
					}
				}
			}}`, codeId),
		},
		{
			name:      "Open Source: snyk-id and repository-url conditions, no meta",
			findingId: testOpenSourceId,
			expectedBody: `{"data": {
				"type": "policy",
				"attributes": {
					"name": "",
					"action_type": "ignore",
					"action": {"data": {"ignore_type": "wont-fix", "reason": "Test reason", "expires": "2027-03-31T00:00:00Z"}},
					"conditions_group": {
						"logical_operator": "and",
						"conditions": [
							{"field": "snyk-id", "operator": "includes", "value": "SNYK-JS-LODASH-567746"},
							{"field": "repository-url", "operator": "includes", "value": "https://github.com/org/repo"}
						]
					}
				}
			}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			run := setupIgnoreCreateRun(t, false, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewPending))
			run.config.Set(FindingsIdKey, tc.findingId)

			_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
			require.NoError(t, err)

			orgId := run.config.GetString(configuration.ORGANIZATION)
			assert.Equal(t, []string{"POST https://api.snyk.io/rest/orgs/" + orgId + "/policies?version=2024-10-15"}, run.requests)
			require.Len(t, run.requestBodies, 1)
			assert.JSONEq(t, tc.expectedBody, run.requestBodies[0])
		})
	}
}

func Test_ignoreCreateWorkflowEntryPoint_repoUrl(t *testing.T) {
	testCases := []struct {
		name                      string
		flagUrl                   string // --remote-repo-url, not set when empty
		originUrl                 string // first URL of the origin remote, no git repository when empty
		expectedRepoUrl           string // in the meta of a Snyk Code ignore
		expectedOpenSourceRepoUrl string // in the condition and the output of an Open Source ignore
	}{
		{
			name:                      "--remote-repo-url is used over origin",
			flagUrl:                   "https://github.com/org/flag-repo.git",
			originUrl:                 "https://github.com/org/origin-repo.git",
			expectedRepoUrl:           "https://github.com/org/flag-repo.git",
			expectedOpenSourceRepoUrl: "https://github.com/org/flag-repo",
		},
		{name: "credentials are stripped from --remote-repo-url", flagUrl: testRepoUrlWithCredentials, expectedRepoUrl: testCleanRepoUrl, expectedOpenSourceRepoUrl: testNormalizedRepoUrl},
		{name: "origin is used without --remote-repo-url", originUrl: "https://github.com/org/origin-repo.git", expectedRepoUrl: "https://github.com/org/origin-repo.git", expectedOpenSourceRepoUrl: "https://github.com/org/origin-repo"},
		{name: "credentials are stripped from origin", originUrl: testRepoUrlWithCredentials, expectedRepoUrl: testCleanRepoUrl, expectedOpenSourceRepoUrl: testNormalizedRepoUrl},
		{name: "SSH origin only loses its user", originUrl: "git@github.com:org/repo.git", expectedRepoUrl: "github.com:org/repo.git", expectedOpenSourceRepoUrl: "github.com:org/repo"},
	}

	for _, tc := range testCases {
		for _, findingId := range []string{uuid.New().String(), testOpenSourceId} {
			openSource := findingId == testOpenSourceId
			t.Run(fmt.Sprintf("%s (open source=%t)", tc.name, openSource), func(t *testing.T) {
				run := setupIgnoreCreateRun(t, true, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewApproved))
				run.config.Set(FindingsIdKey, findingId)
				if tc.flagUrl != "" {
					run.config.Set(RemoteRepoUrlKey, tc.flagUrl)
				}
				inputDir := t.TempDir() // not a git repository
				if tc.originUrl != "" {
					inputDir = initRepoWithOrigin(t, tc.originUrl)
				}
				run.config.Set(configuration.INPUT_DIRECTORY, inputDir)

				_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
				require.NoError(t, err)

				require.Len(t, run.requestBodies, 1)
				var payload policyApi.CreatePolicyPayload
				require.NoError(t, json.Unmarshal([]byte(run.requestBodies[0]), &payload))
				output := strings.Join(run.events, "")
				if openSource {
					require.Len(t, payload.Data.Attributes.ConditionsGroup.Conditions, 2)
					assert.Equal(t, tc.expectedOpenSourceRepoUrl, payload.Data.Attributes.ConditionsGroup.Conditions[1].Value)
					assert.Contains(t, output, "\n  Repository:    "+tc.expectedOpenSourceRepoUrl+"\n")
					assert.Contains(t, output, " in "+tc.expectedOpenSourceRepoUrl+".\n")
				} else {
					require.NotNil(t, payload.Data.Meta)
					assert.Equal(t, tc.expectedRepoUrl, (*payload.Data.Meta)["repo_url"])
				}
				assert.NotContains(t, run.requestBodies[0], "SECRET")
				assert.NotContains(t, output, "SECRET")
			})
		}
	}
}

func Test_ignoreCreateWorkflowEntryPoint_openSourceRepoUrlNormalized(t *testing.T) {
	testCases := []struct {
		name            string
		flagUrl         string // --remote-repo-url, not set when empty
		originUrl       string // first URL of the origin remote
		expectedRepoUrl string
	}{
		{name: "origin ending in .git loses the suffix", originUrl: "https://github.com/org/repo.git", expectedRepoUrl: testNormalizedRepoUrl},
		{name: "origin ending in a slash loses the slash", originUrl: "https://github.com/org/repo/", expectedRepoUrl: testNormalizedRepoUrl},
		{
			name:            "--remote-repo-url without a suffix is unchanged",
			flagUrl:         "https://github.com/org/flag-repo",
			originUrl:       testCleanRepoUrl,
			expectedRepoUrl: "https://github.com/org/flag-repo",
		},
		{name: "origin with credentials and .git loses both", originUrl: testRepoUrlWithCredentials, expectedRepoUrl: testNormalizedRepoUrl},
	}

	for _, tc := range testCases {
		for _, interactive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s (interactive=%t)", tc.name, interactive), func(t *testing.T) {
				run := setupIgnoreCreateRun(t, interactive, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewApproved))
				run.config.Set(FindingsIdKey, testOpenSourceId)
				if tc.flagUrl != "" {
					run.config.Set(RemoteRepoUrlKey, tc.flagUrl)
				}
				run.config.Set(configuration.INPUT_DIRECTORY, initRepoWithOrigin(t, tc.originUrl))

				_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
				require.NoError(t, err)

				require.Len(t, run.requestBodies, 1)
				var payload policyApi.CreatePolicyPayload
				require.NoError(t, json.Unmarshal([]byte(run.requestBodies[0]), &payload))
				conditions := payload.Data.Attributes.ConditionsGroup.Conditions
				require.Len(t, conditions, 2)
				assert.Equal(t, policyApi.PolicyCreateRepositoryURL, conditions[1].Field)
				assert.Equal(t, tc.expectedRepoUrl, conditions[1].Value)
				assert.Contains(t, run.events, "\n  ✅ Ignore created for "+testOpenSourceId+" in "+tc.expectedRepoUrl+".\n")
				assert.NotContains(t, run.requestBodies[0], "SECRET")
				assert.NotContains(t, strings.Join(run.events, ""), "SECRET")
			})
		}
	}
}

func Test_normalizeOpenSourceRepoUrl(t *testing.T) {
	testCases := []struct {
		name     string
		repoUrl  string
		expected string
	}{
		{name: "URL without a suffix is unchanged", repoUrl: "https://github.com/org/repo", expected: "https://github.com/org/repo"},
		{name: ".git is removed", repoUrl: "https://github.com/org/repo.git", expected: "https://github.com/org/repo"},
		{name: "trailing slash is removed", repoUrl: "https://github.com/org/repo/", expected: "https://github.com/org/repo"},
		{name: "trailing slash is removed before .git", repoUrl: "https://github.com/org/repo.git/", expected: "https://github.com/org/repo"},
		{name: "surrounding whitespace is removed first", repoUrl: " \thttps://github.com/org/repo.git/\n", expected: "https://github.com/org/repo"},
		{name: "only one trailing slash is removed", repoUrl: "https://github.com/org/repo//", expected: "https://github.com/org/repo/"},
		{name: ".git is case-sensitive", repoUrl: "https://github.com/org/repo.GIT", expected: "https://github.com/org/repo.GIT"},
		{name: "SCP-style URL only loses .git", repoUrl: "github.com:org/repo.git", expected: "github.com:org/repo"},
		{name: "empty URL stays empty", repoUrl: "", expected: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, normalizeOpenSourceRepoUrl(tc.repoUrl))
		})
	}
}

func Test_ignoreCreateWorkflowEntryPoint_openSourceRepoUrlNormalizedToEmpty(t *testing.T) {
	testCases := []struct {
		name    string
		flagUrl string // --remote-repo-url, used over the origin of the clone
	}{
		{name: "--remote-repo-url=.git", flagUrl: ".git"},
		{name: "--remote-repo-url of a slash between spaces", flagUrl: " / "},
	}

	for _, tc := range testCases {
		for _, interactive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s (interactive=%t)", tc.name, interactive), func(t *testing.T) {
				run := setupIgnoreCreateRun(t, interactive, "{}")
				run.config.Set(FindingsIdKey, testOpenSourceId)
				run.config.Set(RemoteRepoUrlKey, tc.flagUrl)

				_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

				var snykErr snyk_errors.Error
				require.ErrorAs(t, err, &snykErr)
				assert.Equal(t, "SNYK-CLI-0003", snykErr.ErrorCode)
				assert.Equal(t, "The remote repository URL could not be automatically detected. Provide it using the --remote-repo-url flag.", snykErr.Detail)
				assert.Empty(t, run.requests, "an empty repository URL must send no request")
				assert.Zero(t, run.whoamiCalls, "an empty repository URL must not call whoami")
			})
		}
	}
}

func Test_ignoreCreateWorkflowEntryPoint_emptyFlagErrors(t *testing.T) {
	t.Run("non-interactive without --finding-id", func(t *testing.T) {
		run := setupIgnoreCreateRun(t, false, "{}")

		_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

		var snykErr snyk_errors.Error
		require.ErrorAs(t, err, &snykErr)
		assert.Equal(t, "SNYK-CLI-0003", snykErr.ErrorCode)
		assert.Equal(t, "The finding-id is required. Provide it using the --finding-id flag.", snykErr.Detail)
		assert.Empty(t, run.requests)
		assert.Zero(t, run.whoamiCalls)
	})

	noRemoteDirs := []struct {
		name string
		dir  func(t *testing.T) string
	}{
		{
			name: "not a git repository",
			dir: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
		},
		{
			name: "git repository without origin",
			dir: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				_, err := gogit.PlainInit(dir, false)
				require.NoError(t, err)
				return dir
			},
		},
	}
	for _, noRemote := range noRemoteDirs {
		for _, findingId := range []string{uuid.New().String(), testOpenSourceId} {
			t.Run(fmt.Sprintf("non-interactive without --remote-repo-url in %s (finding id %s)", noRemote.name, findingId), func(t *testing.T) {
				run := setupIgnoreCreateRun(t, false, "{}")
				run.config.Set(FindingsIdKey, findingId)
				run.config.Set(configuration.INPUT_DIRECTORY, noRemote.dir(t))

				_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

				var snykErr snyk_errors.Error
				require.ErrorAs(t, err, &snykErr)
				assert.Equal(t, "SNYK-CLI-0003", snykErr.ErrorCode)
				assert.Equal(t, "The remote repository URL could not be automatically detected. Provide it using the --remote-repo-url flag.", snykErr.Detail)
				assert.Empty(t, run.requests)
				assert.Zero(t, run.whoamiCalls)
			})
		}
	}

	t.Run("interactive without a detected remote prompts for it", func(t *testing.T) {
		run := setupIgnoreCreateRun(t, true, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewApproved))
		run.config.Set(FindingsIdKey, testOpenSourceId)
		run.config.Set(configuration.INPUT_DIRECTORY, t.TempDir()) // not a git repository
		run.userInterface.EXPECT().Input(remoteRepoUrlDescription).Return(testRepoUrlWithCredentials, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
		require.NoError(t, err)

		require.Len(t, run.requestBodies, 1)
		var payload policyApi.CreatePolicyPayload
		require.NoError(t, json.Unmarshal([]byte(run.requestBodies[0]), &payload))
		assert.Equal(t, testNormalizedRepoUrl, payload.Data.Attributes.ConditionsGroup.Conditions[1].Value)
	})
}

func Test_ignoreCreateWorkflowEntryPoint_openSourceOutput(t *testing.T) {
	createdLine := "\n  ✅ Ignore created for SNYK-JS-LODASH-567746 in https://github.com/org/repo.\n"
	pendingLine := "\n  Your ignore request has been submitted. It applies after an approver accepts it.\n"
	testCases := []struct {
		review       policyApi.PolicyReview
		expectedLast string
	}{
		{review: policyApi.PolicyReviewApproved, expectedLast: createdLine},
		{review: policyApi.PolicyReviewNotRequired, expectedLast: createdLine},
		{review: policyApi.PolicyReviewPending, expectedLast: pendingLine},
	}

	for _, tc := range testCases {
		t.Run("interactive, review "+string(tc.review), func(t *testing.T) {
			run := setupIgnoreCreateRun(t, true, getOpenSourcePolicyResponse(t, tc.review))
			run.config.Set(FindingsIdKey, testOpenSourceId)

			_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
			require.NoError(t, err)

			details := "\n  Organization:  " + testOrgSlug +
				"\n  Requested on:  " + time.Now().Format(time.DateOnly) +
				"\n  Requested by:  " + expectedUser +
				"\n  Snyk ID:       SNYK-JS-LODASH-567746" +
				"\n  Repository:    https://github.com/org/repo" +
				"\n  Expiration:    2027-03-31" +
				"\n  Ignore type:   wont-fix" +
				"\n  Reason:        Test reason"
			assert.Equal(t, []string{scopeLineOpenSource, details, requestSentEvent, tc.expectedLast}, run.events)
		})

		t.Run("non-interactive, review "+string(tc.review), func(t *testing.T) {
			run := setupIgnoreCreateRun(t, false, getOpenSourcePolicyResponse(t, tc.review))
			run.config.Set(FindingsIdKey, testOpenSourceId)

			_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
			require.NoError(t, err)

			assert.Equal(t, []string{requestSentEvent, scopeLineOpenSource, tc.expectedLast}, run.events)
		})
	}

	t.Run("interactive, id typed at the prompt", func(t *testing.T) {
		run := setupIgnoreCreateRun(t, true, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewPending))
		run.userInterface.EXPECT().Input(findingsIdDescription).Return(testOpenSourceId, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
		require.NoError(t, err)

		require.Len(t, run.events, 5)
		assert.Equal(t, []string{findingIdPromptOutput, scopeLineOpenSource}, run.events[:2])
		assert.Equal(t, []string{requestSentEvent, pendingLine}, run.events[3:])
	})
}

func Test_ignoreCreateWorkflowEntryPoint_snykCodeOutput(t *testing.T) {
	findingId := uuid.New().String()
	response := getSuccessfulPolicyResponse(uuid.New().String(), findingId, string(policyApi.WontFix), testReason, expectedUser, nil)
	details := "\n  Organization:  " + testOrgSlug +
		"\n  Requested on:  " + time.Now().Format(time.DateOnly) +
		"\n  Requested by:  " + expectedUser +
		"\n  Expiration:    2027-03-31" +
		"\n  Ignore type:   wont-fix" +
		"\n  Reason:        Test reason"
	submittedLine := "\n  ✅ Your ignore request has been submitted.\n"

	t.Run("interactive", func(t *testing.T) {
		run := setupIgnoreCreateRun(t, true, response)
		run.config.Set(FindingsIdKey, findingId)

		_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
		require.NoError(t, err)

		assert.Equal(t, []string{scopeLineSnykCode, details, requestSentEvent, submittedLine}, run.events)
	})

	t.Run("interactive, id typed at the prompt", func(t *testing.T) {
		run := setupIgnoreCreateRun(t, true, response)
		run.userInterface.EXPECT().Input(findingsIdDescription).Return(findingId, nil).Times(1)

		_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
		require.NoError(t, err)

		// the product is known only once the id is typed, so the line about it follows the prompt
		assert.Equal(t, []string{findingIdPromptOutput, scopeLineSnykCode, details, requestSentEvent, submittedLine}, run.events)
	})

	t.Run("non-interactive", func(t *testing.T) {
		run := setupIgnoreCreateRun(t, false, response)
		run.config.Set(FindingsIdKey, findingId)

		_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
		require.NoError(t, err)

		assert.Equal(t, []string{requestSentEvent}, run.events)
	})
}

func Test_getOpenSourceIgnoreResultMessage(t *testing.T) {
	createdMessage := "✅ Ignore created for SNYK-JS-LODASH-567746 in https://github.com/org/repo.git."
	pendingMessage := "Your ignore request has been submitted. It applies after an approver accepts it."
	testCases := []struct {
		review   policyApi.PolicyReview
		expected string
	}{
		{review: policyApi.PolicyReviewApproved, expected: createdMessage},
		{review: policyApi.PolicyReviewNotRequired, expected: createdMessage},
		{review: policyApi.PolicyReviewPending, expected: pendingMessage},
		{review: policyApi.PolicyReviewRejected, expected: pendingMessage},
		{review: "", expected: pendingMessage},
	}

	for _, tc := range testCases {
		t.Run("review "+string(tc.review), func(t *testing.T) {
			assert.Equal(t, tc.expected, getOpenSourceIgnoreResultMessage(tc.review, testOpenSourceId, testCleanRepoUrl))
		})
	}
}

func Test_ignoreCreateWorkflowEntryPoint_serverErrors(t *testing.T) {
	errorHandlers := []struct {
		name    string
		handler networktypes.ErrorHandlerFunc
	}{
		{name: "an error handler like the Snyk CLI's", handler: func(err error, _ context.Context) error { return err }},
		{name: "no error handler"},
	}
	testCases := []struct {
		statusCode int
		detail     string
	}{
		{statusCode: http.StatusForbidden, detail: "Detail of the forbidden request."},
		{statusCode: http.StatusConflict, detail: "Detail of the conflict."},
		{statusCode: http.StatusUnprocessableEntity, detail: "Detail of the unprocessable request."},
		{statusCode: http.StatusServiceUnavailable, detail: "Detail of the unavailable service."},
	}

	for _, errorHandler := range errorHandlers {
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("%d with %s", tc.statusCode, errorHandler.name), func(t *testing.T) {
				title := http.StatusText(tc.statusCode)
				body, err := json.Marshal(policyApi.ErrorDocument{
					Jsonapi: policyApi.JsonApi{Version: "1.0"},
					Errors:  []policyApi.Error{{Status: strconv.Itoa(tc.statusCode), Title: &title, Detail: tc.detail}},
				})
				require.NoError(t, err)
				run := setupIgnoreCreateRunWithServer(t, errorHandler.handler, tc.statusCode, "application/vnd.api+json", string(body))

				_, err = ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

				var snykErr snyk_errors.Error
				require.ErrorAs(t, err, &snykErr)
				assert.Equal(t, title, snykErr.Title)
				assert.Equal(t, tc.detail, snykErr.Detail)
				assert.Equal(t, tc.statusCode, snykErr.StatusCode)
			})
		}

		t.Run("non-201 without a JSON:API body with "+errorHandler.name, func(t *testing.T) {
			run := setupIgnoreCreateRunWithServer(t, errorHandler.handler, http.StatusConflict, "text/plain", "conflict")

			_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

			require.Error(t, err)
			assert.Equal(t, "error sending request: Status 409 Conflict StatusCode 409", err.Error())
		})
	}
}

func Test_ignoreCreateWorkflowEntryPoint_openSourceEnrichedResponse(t *testing.T) {
	run := setupIgnoreCreateRun(t, false, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewNotRequired))
	run.config.Set(FindingsIdKey, testOpenSourceId)
	run.config.Set(EnrichResponseKey, true)

	result, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)
	require.NoError(t, err)

	require.Len(t, result, 1)
	assert.Equal(t, "application/json", result[0].GetContentType())
	data, ok := result[0].GetPayload().([]byte)
	require.True(t, ok)
	var suppression sarif.Suppression
	require.NoError(t, json.Unmarshal(data, &suppression))
	assert.Equal(t, testOpenSourcePolicyId, suppression.Guid)
	assert.Equal(t, sarif.Accepted, suppression.Status)
	assert.Equal(t, testReason, suppression.Justification)
	assert.Equal(t, string(policyApi.WontFix), string(suppression.Properties.Category))
}

func Test_ignoreCreateWorkflowEntryPoint_openSourceWithIgnoreApprovalWorkflowOff(t *testing.T) {
	// whether an Open Source ignore can be created is the server's decision, so the workflow sends the request
	run := setupIgnoreCreateRun(t, false, getOpenSourcePolicyResponse(t, policyApi.PolicyReviewNotRequired))
	run.config.Set(ConfigIgnoreApprovalEnabled, false)
	run.config.Set(FindingsIdKey, testOpenSourceId)

	_, err := ignoreCreateWorkflowEntryPoint(run.invocationCtx, nil)

	require.NoError(t, err)
	assert.Len(t, run.requests, 1)
}

func Test_getOrgIgnoreApprovalEnabled_CacheDependentOnOrg(t *testing.T) {
	testutils.CheckCacheRespectOrgDependency(
		t,
		ConfigIgnoreApprovalEnabled,
		func(isFirstCall bool) any {
			return &contract.OrgSettingsResponse{
				Ignores: &contract.OrgIgnoreSettings{
					ApprovalWorkflowEnabled: isFirstCall,
				},
			}
		},
		InitIgnoreWorkflows,
		true,
		false,
	)
}
