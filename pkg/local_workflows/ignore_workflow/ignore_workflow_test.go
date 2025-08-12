package ignore_workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api/contract"
	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/mocks"
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

	// setup
	logger := zerolog.Logger{}
	config := configuration.New()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.ORGANIZATION, uuid.New().String())
	config.Set(ConfigIgnoreApprovalEnabled, true)
	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	mockUserInterface := mocks.NewMockUserInterface(ctrl)
	mockEngine := mocks.NewMockEngine(ctrl)

	mockUserInterface.EXPECT().Output(gomock.Any()).Return(nil).AnyTimes()
	mockUserInterface.EXPECT().Input(gomock.Any()).Return("", nil).AnyTimes()

	httpClient := localworkflows.NewTestClient(func(req *http.Request) *http.Response {
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
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	invocationContextMock.EXPECT().GetUserInterface().Return(mockUserInterface).AnyTimes()
	invocationContextMock.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier(ignoreCreateWorkflowName)).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
	mockData := []workflow.Data{workflow.NewData(
		workflow.NewTypeIdentifier(localworkflows.WORKFLOWID_WHOAMI, "whoami"),
		"text/plain",
		expectedUser,
		workflow.WithLogger(&logger),
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
	assert.Equal(t, policyApi.Snykassetfindingv1, payload.Data.Attributes.ConditionsGroup.Conditions[0].Field, "Should have correct findings ID")
	assert.Equal(t, policyApi.Includes, payload.Data.Attributes.ConditionsGroup.Conditions[0].Operator, "Condition operation must be include")
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
	t.Run("IAW FF is disabled", func(t *testing.T) {
		expectedFindingsId := uuid.New().String()
		expectedIgnoreType := string(policyApi.WontFix)
		expectedReason := "Test reason"

		invocationContext := setupMockIgnoreContext(t, "{}", http.StatusCreated)
		config := invocationContext.GetConfiguration()
		config.Set(ConfigIgnoreApprovalEnabled, false)

		config.Set(InteractiveKey, false)

		config.Set(FindingsIdKey, expectedFindingsId)
		config.Set(IgnoreTypeKey, expectedIgnoreType)
		config.Set(ReasonKey, expectedReason)
		config.Set(RemoteRepoUrlKey, testRepoUrl)
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(EnrichResponseKey, true)

		result, err := ignoreCreateWorkflowEntryPoint(invocationContext, nil)
		assert.NotNil(t, err, "Should return an error when IAW FF is disabled")
		assert.Nil(t, result, "result should be nil when IAW FF is disabled")
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

	httpClient := localworkflows.NewTestClient(func(req *http.Request) *http.Response {
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
					ActionType: policyApi.PolicyResponseAttributesActionTypeIgnore,
					ConditionsGroup: policyApi.PolicyConditionsGroup{
						Conditions: []policyApi.PolicyCondition{
							{
								Field:    policyApi.Snykassetfindingv1,
								Operator: policyApi.Includes,
								Value:    findingId,
							},
						},
						LogicalOperator: policyApi.And,
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

		httpClient := localworkflows.NewTestClient(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString("Internal Server Error")),
			}
		})

		mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
		mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess)
		mockEngine.EXPECT().GetLogger().Return(&logger)
		mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return(orgId)
		mockConfig.EXPECT().GetString(configuration.API_URL).Return(apiUrl)
		mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient)

		defaultValueFunc := getOrgIgnoreApprovalEnabled(mockEngine)
		result, err := defaultValueFunc(nil, nil)

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

	httpClient := localworkflows.NewTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
		}
	})

	mockEngine.EXPECT().GetConfiguration().Return(mockConfig)
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess)
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return(orgId)
	mockConfig.EXPECT().GetString(configuration.API_URL).Return(apiUrl)
	mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient)

	defaultValueFunc := getOrgIgnoreApprovalEnabled(mockEngine)
	return defaultValueFunc(nil, nil)
}
