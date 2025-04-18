package ignore_workflow

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
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
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
	expireDate, err := time.Parse(time.DateOnly, "2025-01-01")
	assert.NoError(t, err)
	userName := "test-user"
	ignoreType := "wont-fix"
	ordId := uuid.New().String()
	result := getIgnoreRequestDetailsStructure(&expireDate, userName, ordId, ignoreType)

	assert.Contains(t, result, "2025-01-01")
	assert.Contains(t, result, userName)
	assert.Contains(t, result, ignoreType)
	assert.Contains(t, result, ordId)
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
		assert.Nil(t, policyResp.Properties.Expiration)
		assert.Equal(t, expectedReason, policyResp.Justification)
	})
}
