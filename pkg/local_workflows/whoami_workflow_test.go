package localworkflows

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"

	"github.com/stretchr/testify/assert"
)

const referenceUrl = "/rest/self?version=2024-04-22"

func Test_WhoAmI_whoAmIWorkflowEntryPoint_requireExperimentalFlag(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	config.Set("experimental", false)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	// setup invocation context
	invocationContextMock.EXPECT().GetConfiguration().Return(config)
	invocationContextMock.EXPECT().GetLogger().Return(logger)
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock)
	networkAccessMock.EXPECT().GetHttpClient().Return(http.DefaultClient).AnyTimes()

	expectedError := errors.New("set `--experimental` flag to enable whoAmI command")

	// run test
	_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)
	assert.Equal(t, expectedError.Error(), err.Error())
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_happyPath(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	config.Set("experimental", true)

	// Snyk API payload mock response
	payload := `{
		"Data": {
		  "attributes": {
			"avatar_url": "https://snyk.io/avatar.png",
			"default_org_context": "18f054da-5e70-4000-8b3d-43783a372b01",
			"email": "user.name@snyk.io",
			"name": "user",
			"username": "user.name@snyk.io"
		  },
		  "id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4121",
		  "type": "principal"
		}		
	  }`

	// JSON reference of what the user should receive when passing the json flag
	jsonOutput := `{
		"id": "55a348e2-c3ad-4bbc-b40e-9b232d1f4121",
		"username": "user.name@snyk.io",
		"email": "user.name@snyk.io"
		}`

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		assert.Equal(t, referenceUrl, req.URL.String())
		assert.Equal(t, "GET", req.Method)

		return &http.Response{
			StatusCode: http.StatusOK,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBufferString(payload)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	t.Run("returns user name", func(t *testing.T) {
		// setup
		expectedResponse := "user.name@snyk.io"

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, expectedResponse, output[0].GetPayload())
		assert.Equal(t, "text/plain", output[0].GetContentType())
	})

	t.Run("json flag returns full json response", func(t *testing.T) {
		// setup
		config.Set("json", true)

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)

		var expected interface{}
		err = json.Unmarshal([]byte(jsonOutput), &expected)
		assert.Nil(t, err)

		var actual interface{}
		err = json.Unmarshal(output[0].GetPayload().([]byte), &actual)
		assert.Nil(t, err)

		assert.Equal(t, expected, actual)
		assert.Equal(t, "application/json", output[0].GetContentType())
	})
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_fetchUserFailures(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	config.Set("experimental", true)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()

	t.Run("handles unauthorized access", func(t *testing.T) {
		// setup
		mockClient := newTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			assert.Equal(t, referenceUrl, req.URL.String())
			assert.Equal(t, "GET", req.Method)

			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				// Send response to be tested
				Body: io.NopCloser(bytes.NewBufferString("")),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		})
		networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).Times(1)

		expectedError := errors.New("error fetching user data: error while fetching self data: API request failed (status: 401)")

		// execute
		_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Equal(t, expectedError.Error(), err.Error())
	})

	t.Run("handles unknown statusCode", func(t *testing.T) {
		// setup
		mockClient := newTestClient(func(req *http.Request) *http.Response {
			// Test request parameters
			assert.Equal(t, referenceUrl, req.URL.String())
			assert.Equal(t, "GET", req.Method)

			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				// Send response to be tested
				Body: io.NopCloser(bytes.NewBufferString("")),
				// Must be set to non-nil value or it panics
				Header: make(http.Header),
			}
		})
		networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).Times(1)

		expectedError := errors.New("error fetching user data: error while fetching self data: API request failed (status: 500)")

		// execute
		_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Equal(t, expectedError.Error(), err.Error())
	})
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint_extractUserFailures(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	config.Set("experimental", true)

	payloadMissingUserNameProperty := `{
		"id": "88c4a3b3-ac23-4cbe-8c28-228ff614910b",
		"email": "user.email@snyk.io",
		"orgs": [
				{
					"name": "Snyk AppSec",
					"id": "4a3d29ab-6612-481b-83f2-aea6cf421ea5",
					"group": {
						"name": "snyk-sec-prod",
						"id": "dd36a3c3-0e57-4702-81e6-a0e099e045a0"
					}
				}
			]
		}`

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		assert.Equal(t, referenceUrl, req.URL.String())
		assert.Equal(t, "GET", req.Method)

		return &http.Response{
			StatusCode: http.StatusOK,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBufferString(payloadMissingUserNameProperty)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	// setup
	expectedError := errors.New("error fetching user data: error while extracting user: missing properties username/name")

	// execute
	_, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

	// assert
	assert.Error(t, err)
	assert.Equal(t, expectedError.Error(), err.Error())
}
