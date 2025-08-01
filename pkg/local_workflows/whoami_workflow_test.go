package localworkflows

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/rs/zerolog"

	"github.com/golang/mock/gomock"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"

	"github.com/stretchr/testify/assert"
)

const referenceUrl = "/rest/self?version=2024-04-22"

// Snyk API payload mock responses
const happyPayloadRegularUser string = `{
	"jsonapi": {
	  "version": "1.0"
	},
	"data": {
	  "type": "user",
	  "id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4122",
	  "attributes": {
		"name": "jane doe",
		"default_org_context": "55a348e2-c3ad-4bbc-b40e-9b232d1f4121",
		"username": "jane.doe@snyk.io",
		"email": "jane.doe@snyk.io",
		"avatar_url": "https://s.gravxyztar.com/avatar/jane.doe@snyk.io.png"
	  }
	},
	"links": {
	  "self": "/self?version=2024-04-22"
	}
  }`

const happyPayloadServiceUser string = `{
	"jsonapi": {
	  "version": "1.0"
	},
	"data": {
	  "type": "service_account",
	  "id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4122",
	  "attributes": {
		"name": "development",
		"default_org_context": "55a348e2-c3ad-4bbc-b40e-9b232d1f4121"
	  }
	},
	"links": {
	  "self": "/self?version=2024-04-22"
	}
  }`

const missingFieldsPayload string = `{
	"jsonapi": {
		"version": "1.0"
	  },
	  "data": {
		"type": "service_account",
		"id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4122",
		"attributes": {
		  "default_org_context": "55a348e2-c3ad-4bbc-b40e-9b232d1f4121"
		}
	  },
	  "links": {
		"self": "/self?version=2024-04-22"
	  }
	}`

func setupMockContext(t *testing.T, payload string, experimental bool, json bool, statusCode int, mockClient bool) *mocks.MockInvocationContext {
	// This method is a helper
	t.Helper()

	// setup
	logger := zerolog.Logger{}
	config := configuration.New()
	config.Set("experimental", experimental)
	config.Set("json", json)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	var httpClient *http.Client = http.DefaultClient

	if mockClient {
		httpClient = NewTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			assert.Equal(t, referenceUrl, req.URL.String())
			assert.Equal(t, "GET", req.Method)

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
	invocationContextMock.EXPECT().GetConfiguration().Return(config)
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger)
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock)
	networkAccessMock.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()

	return invocationContextMock
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_requireExperimentalFlag(t *testing.T) {
	// Setup test environment
	invocationContextMock := setupMockContext(t, "", false, false, http.StatusOK, false)

	// Assert - whoami is only available with --experiimental flag
	expectedError := errors.New("set `--experimental` flag to enable whoAmI command")

	// run test
	_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)
	assert.Equal(t, expectedError.Error(), err.Error())
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_happyPathRegularUser(t *testing.T) {
	// JSON reference of what the user should receive when passing the json flag
	jsonOutput := `{
		"id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4122",
		"name":"jane doe",
		"username": "jane.doe@snyk.io",
		"email": "jane.doe@snyk.io"
		}`

	t.Run("returns user name", func(t *testing.T) {
		// Setup test environment
		invocationContextMock := setupMockContext(t, happyPayloadRegularUser, true, false, http.StatusOK, true)
		// Expected response is the username
		expectedResponse := "jane.doe@snyk.io"

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, expectedResponse, output[0].GetPayload())
		assert.Equal(t, "text/plain", output[0].GetContentType())
	})

	t.Run("json flag returns full json response", func(t *testing.T) {
		// Setup test environment
		invocationContextMock := setupMockContext(t, happyPayloadRegularUser, true, true, http.StatusOK, true)

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)

		var expected interface{}
		err = json.Unmarshal([]byte(jsonOutput), &expected)
		assert.Nil(t, err)

		var actual interface{}
		err = json.Unmarshal(output[0].GetPayload().([]byte), &actual) //nolint:errcheck //in this test, the type is clear
		assert.Nil(t, err)

		// The output should be a dump of the data from the API in json format
		assert.Equal(t, expected, actual)
		assert.Equal(t, "application/json", output[0].GetContentType())
	})
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_happyPathServiceUser(t *testing.T) {
	// JSON reference of what the user should receive when passing the json flag
	jsonOutput := `{
		"id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4122",
		"name": "development",
		"username": "",
		"email": ""
		}`

	t.Run("returns user name", func(t *testing.T) {
		// Setup test environment
		invocationContextMock := setupMockContext(t, happyPayloadServiceUser, true, false, http.StatusOK, true)

		// For a service account returns the name given when creating the token
		expectedResponse := "development"

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, expectedResponse, output[0].GetPayload())
		assert.Equal(t, "text/plain", output[0].GetContentType())
	})

	t.Run("json flag returns full json response", func(t *testing.T) {
		// Setup test environment
		invocationContextMock := setupMockContext(t, happyPayloadServiceUser, true, true, http.StatusOK, true)

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)

		var expected interface{}
		err = json.Unmarshal([]byte(jsonOutput), &expected)
		assert.Nil(t, err)

		var actual interface{}
		err = json.Unmarshal(output[0].GetPayload().([]byte), &actual) //nolint:errcheck //in this test, the type is clear
		assert.Nil(t, err)

		// The output should be a dump of the data from the API in json format
		assert.Equal(t, expected, actual)
		assert.Equal(t, "application/json", output[0].GetContentType())
	})
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_fetchUserFailures(t *testing.T) {
	t.Run("handles unauthorized access", func(t *testing.T) {
		// Setup test environment
		invocationContextMock := setupMockContext(t, "", true, true, http.StatusUnauthorized, true)

		// Should throw this error when res is 401
		expectedError := errors.New("error fetching user data: error while fetching self data: API request failed (status: 401)")

		// execute
		_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Equal(t, expectedError.Error(), err.Error())
	})

	t.Run("handles unknown statusCode", func(t *testing.T) {
		// Setup test environment
		invocationContextMock := setupMockContext(t, "", true, true, http.StatusInternalServerError, true)

		// Should throw this error when res is 500
		expectedError := errors.New("error fetching user data: error while fetching self data: API request failed (status: 500)")

		// execute
		_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Equal(t, expectedError.Error(), err.Error())
	})
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_extractUserFailures(t *testing.T) {
	// Setup test environment
	invocationContextMock := setupMockContext(t, missingFieldsPayload, true, true, http.StatusOK, true)

	// Expected error, the response is missing all of the fields name/email/username
	expectedError := errors.New("error fetching user data: error while extracting user: missing properties username/name")

	// execute
	_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

	// assert
	assert.Error(t, err)
	assert.Equal(t, expectedError.Error(), err.Error())
}
