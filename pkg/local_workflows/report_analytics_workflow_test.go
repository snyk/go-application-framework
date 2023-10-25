package localworkflows

import (
	"bytes"
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

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_happyPath(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)

	requestPayload := `{
		"data": {
			"type": "analytics",
			"attributes": {
				"deviceId": "unique-uuid",
				"application": "snyk-cli",
				"application_version": "1.1233.0",
				"os": "macOS",
				"arch": "ARM64",
							"integration_name": "IntelliJ",
							"integration_version": "2.5.5",
							"integration_environment": "Pycharm",
							"integration_environment_version": "2023.1",
				"event_type": "Scan done",
				"status": "Succeeded",
				"scan_type": "Snyk Open Source",
				"unique_issue_count": {
						"critical": 15,
											"high": 10,
						"medium": 1,
						"low": 2
				},
				"duration_ms": "1000",
				"timestamp_finished": "2023-09-01T12:00:00Z"
			}
		}
	}`

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		assert.Equal(t, "/rest/api/orgs/"+orgId+"/analytics", req.URL.String())
		assert.Equal(t, "POST", req.Method)

		return &http.Response{
			StatusCode: 201,
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBufferString(requestPayload)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	reportAnalyticsEntrypoint(invocationContextMock, nil)
}
