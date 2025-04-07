package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
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
func setupMockIgnoreContext(t *testing.T, payload string, statusCode int, mockClient bool) (workflow.Engine, workflow.InvocationContext) {
	t.Helper()

	// setup
	logger := zerolog.Logger{}
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

	var httpClient = http.DefaultClient

	if mockClient {
		httpClient = newTestClient(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: statusCode,
				// Send response to be tested
				Body: io.NopCloser(bytes.NewBufferString(payload)),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		})
	}

	// setup invocation context
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	invocationContextMock.EXPECT().GetUserInterface().Return(mockUserInterface).AnyTimes()
	invocationContextMock.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier(ignoreCreateWorkflowName)).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
	mockData := []workflow.Data{workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, "whoami"),
		"text/plain",
		expectedUser,
		workflow.WithLogger(&logger),
	)}
	mockEngine.EXPECT().InvokeWithConfig(WORKFLOWID_WHOAMI, gomock.Any()).Return(mockData, nil).AnyTimes()

	return mockEngine, invocationContextMock
}

func Test_getIgnoreRequestDetailsStructure(t *testing.T) {
	expireDate, err := time.Parse(time.DateOnly, "2025-01-01")
	assert.NoError(t, err)
	userName := "test-user"
	ignoreType := "wont-fix"

	result := getIgnoreRequestDetailsStructure(expireDate, userName, ignoreType)

	assert.Contains(t, result, "2025-01-01")
	assert.Contains(t, result, userName)
	assert.Contains(t, result, ignoreType)
}

func Test_validIgnoreType(t *testing.T) {
	validTypes := []string{
		string(policyApi.TemporaryIgnore),
		string(policyApi.WontFix),
		string(policyApi.NotVulnerable),
	}

	for _, validType := range validTypes {
		t.Run("valid: "+validType, func(t *testing.T) {
			assert.True(t, validIgnoreType(validType), "Should be a valid ignore type")
		})
	}

	invalidTypes := []string{
		"invalid",
		"",
		"permanently-ignore",
	}

	for _, invalidType := range invalidTypes {
		t.Run("invalid: "+invalidType, func(t *testing.T) {
			assert.False(t, validIgnoreType(invalidType), "Should be an invalid ignore type")
		})
	}
}

func Test_createPolicy(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		_, invocationContext := setupMockIgnoreContext(t, policyResponseJSON, http.StatusCreated, true)

		var input policyApi.CreatePolicyPayload
		input.Data.Type = policyApi.CreatePolicyPayloadDataTypePolicy

		result, err := createPolicy(invocationContext, input, testRepoUrl)

		assert.NoError(t, err, "Should not return an error")
		assert.NotNil(t, result, "Should return a policy response")
		expectedUuid, _ := uuid.Parse("12345678-1234-1234-1234-123456789012")
		assert.Equal(t, expectedUuid, result.Id, "Should have the correct ID")
	})

	t.Run("server error", func(t *testing.T) {
		_, invocationContext := setupMockIgnoreContext(t, "Internal Server Error", http.StatusInternalServerError, true)

		var input policyApi.CreatePolicyPayload
		input.Data.Type = policyApi.CreatePolicyPayloadDataTypePolicy

		_, err := createPolicy(invocationContext, input, testRepoUrl)

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

	payload := createPayload(testRepoUrl, testBranchName, expireDate, ignoreType, reason, findingsId)

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
		_, invocationContext := setupMockIgnoreContext(t, responseMock, http.StatusCreated, true)
		config := invocationContext.GetConfiguration()
		config.Set(interactiveKey, false)

		config.Set(findingsIdKey, expectedFindingsId)
		config.Set(ignoreTypeKey, expectedIgnoreType)
		config.Set(reasonKey, expectedReason)
		config.Set(expirationKey, expectedExpirationDate.Format(time.RFC3339))
		config.Set(remoteRepoUrlKey, testRepoUrl)
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(enrichResponseKey, true)

		result, err := ignoreCreateWorkflowEntryPoint(invocationContext, nil)

		assert.NoError(t, err, "Should not return an error")
		assert.Greater(t, len(result), 0, "Should return result data")
		payload := result[0].GetPayload()
		assert.NotNil(t, payload, "payload should not be nil")

		// Parse the JSON payload
		var policyResp policyApi.PolicyResponse
		err = json.Unmarshal(payload.([]byte), &policyResp)
		assert.NoError(t, err, "Should parse JSON response")
		assert.Equal(t, policyApi.PolicyResponseTypePolicy, policyResp.Type)
		assert.Equal(t, policyApi.TemporaryIgnore, policyResp.Attributes.Action.Data.IgnoreType)
		assert.Equal(t, expectedReason, *policyResp.Attributes.Action.Data.Reason)
		assert.Equal(t, policyId, policyResp.Id.String())
		assert.Equal(t, expectedExpirationDate, *policyResp.Attributes.Action.Data.Expires)
		assert.Equal(t, policyApi.Snykassetfindingv1, policyResp.Attributes.ConditionsGroup.Conditions[0].Field)
		assert.Equal(t, policyApi.Includes, policyResp.Attributes.ConditionsGroup.Conditions[0].Operator)
		assert.Equal(t, expectedFindingsId, policyResp.Attributes.ConditionsGroup.Conditions[0].Value)
	})
}
