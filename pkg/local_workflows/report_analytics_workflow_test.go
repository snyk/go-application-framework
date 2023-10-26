package localworkflows

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_shouldReportToApi(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)

	requestPayload := testGetScanDonePayloadString()

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	testInitReportAnalyticsWorkflow(ctrl)

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/rest/api/orgs/"+orgId+"/analytics", req.URL.String())
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, requestPayload, string(body))

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

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testGetScanDonePayload(requestPayload)})
	require.NoError(t, err)
}
func Test_ReportAnalytics_ReportAnalyticsEntryPoint_reportsHttpStatusError(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)

	requestPayload := testGetScanDonePayloadString()

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	testInitReportAnalyticsWorkflow(ctrl)

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			// error code!
			StatusCode: 500,
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

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testGetScanDonePayload(requestPayload)})
	require.Error(t, err)
}
func Test_ReportAnalytics_ReportAnalyticsEntryPoint_reportsHttpError(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)

	requestPayload := testGetScanDonePayloadString()

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	testInitReportAnalyticsWorkflow(ctrl)

	mockClient := newErrorProducingTestClient(func(req *http.Request) *http.Response { return nil })

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testGetScanDonePayload(requestPayload)})
	require.Error(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_validatesInput(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)

	requestPayload := `{}`

	input := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName), "application/json", []byte(requestPayload))

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	testInitReportAnalyticsWorkflow(ctrl)

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/rest/api/orgs/"+orgId+"/analytics", req.URL.String())
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, requestPayload, string(body))

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

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{input})
	require.Error(t, err)
}
func testGetScanDonePayload(payload string) workflow.Data {
	return workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName), "application/json", []byte(payload))
}

func testGetScanDonePayloadString() string {
	return `{
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
}

func testInitReportAnalyticsWorkflow(ctrl *gomock.Controller) {
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	InitReportAnalyticsWorkflow(engine)
}
