package localworkflows

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"

	"github.com/stretchr/testify/assert"
)

// roundTripFn
type roundTripFn func(req *http.Request) *http.Response

// RoundTrip
func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func newTestClient(fn roundTripFn) *http.Client {
	return &http.Client{
		Transport: roundTripFn(fn),
	}
}

func Test_WhoAmI_whoAmIWorkflowEntryPoint(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	config.Set("experimental", true)

	payload := `{
	"id": "88c4a3b3-ac23-4cbe-8c28-228ff614910b",
	"username": "user.name@snyk.io",
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
		assert.Equal(t, "/v1/user/me", req.URL.String())
		assert.Equal(t, "GET", req.Method)

		return &http.Response{
			StatusCode: 200,
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBufferString(payload)),
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
	})

	t.Run("json flag returns full json response", func(t *testing.T) {
		// setup
		config.Set("json", "--json")

		// execute
		output, err := whoAmIWorkflowEntryPoint(invocationContextMock, nil)

		// assert
		assert.Nil(t, err)

		var expected interface{}
		err = json.Unmarshal([]byte(payload), &expected)
		assert.Nil(t, err)

		var actual interface{}
		err = json.Unmarshal(output[0].GetPayload().([]byte), &actual)
		assert.Nil(t, err)

		assert.Equal(t, expected, actual)
	})
}
