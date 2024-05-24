package localworkflows

import (
	"bytes"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_shouldReportV2AnalyticsPayloadToApi(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(experimentalFlag, true)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	requestPayload := testGetAnalyticsV2PayloadString()
	expectedPayload := requestPayload
	mockClient := testGetMockHTTPClient(t, orgId, requestPayload, expectedPayload)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_shouldConvertScanDoneEventsAndReportToApi(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"
	a := analytics.New()

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(experimentalFlag, true)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	requestPayload := testGetScanDonePayloadString()
	expectedPayload := testGetConvertedScanDonePayloadString()
	mockClient := testGetMockHTTPClient(t, orgId, requestPayload, expectedPayload)

	//invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetAnalytics().Return(a).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
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
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			// error code!
			StatusCode: http.StatusInternalServerError,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBufferString(requestPayload)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
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
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	mockClient := newErrorProducingTestClient(func(req *http.Request) *http.Response { return nil })

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
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
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{input})
	require.Error(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_usesCLIInput(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	requestPayload := testGetScanDonePayloadString()
	expectedPayload := testGetConvertedScanDonePayloadString()
	config.Set("inputData", requestPayload)
	orgId := "orgId"
	a := analytics.New()

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(experimentalFlag, true)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))
	mockClient := testGetMockHTTPClient(t, orgId, requestPayload, expectedPayload)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetAnalytics().Return(a).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_validatesInputJson(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)
	requestPayload := ""

	input := workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName), "application/json", []byte(requestPayload))

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{input})
	require.Error(t, err)
}

func testPayload(payload string) workflow.Data {
	return workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName), "application/json", []byte(payload))
}

func testGetAnalyticsV2PayloadString() string {
	return `{
	  "data": {
		"attributes": {
		  "interaction": {
			"categories": [
			  "code",
			  "test",
			  "experimental"
			],
			"errors": [
			  {
				"id": ""
			  }
			],
			"extension": {
			  "exitcode": 1
			},
			"id": "urn:snyk:interaction:a8f5d5bf-ec4e-4490-8379-fb1b9119cc22",
			"results": [],
			"stage": "dev",
			"status": "success",
			"target": {
			  "id": "pkg:"
			},
			"timestamp_ms": 1716477530074,
			"type": "Scan done"
		  },
		  "runtime": {
			"application": {
			  "name": "snyk-cli",
			  "version": "1.1292.0-dev.306455c62eca7fa28cd9969d2f074f4a1643686d"
			},
			"performance": {
			  "duration_ms": 6307
			},
			"platform": {
			  "arch": "arm64",
			  "os": "darwin"
			}
		  }
		},
		"type": "analytics"
	  }
	}`
}

func testGetScanDonePayloadString() string {
	return `{
		"data": {
			"type": "analytics",
			"attributes": {
				"device_id": "unique-uuid",
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

func testGetConvertedScanDonePayloadString() string {
	return "{\"data\":{\"attributes\":{\"interaction\":{\"categories\":[\"Snyk Open Source\",\"test\"],\"errors\":[],\"extension\":null,\"id\":\"\",\"results\":[{\"count\":15,\"name\":\"critical\"},{\"count\":10,\"name\":\"high\"},{\"count\":1,\"name\":\"medium\"},{\"count\":2,\"name\":\"low\"}],\"stage\":\"dev\",\"status\":\"failure\",\"target\":{\"id\":\"\"},\"timestamp_ms\":1693569600000,\"type\":\"Scan done\"},\"runtime\":{\"application\":{\"name\":\"snyk-cli\",\"version\":\"1.1233.0\"},\"environment\":{\"name\":\"Pycharm\",\"version\":\"2023.1\"},\"integration\":{\"name\":\"IntelliJ\",\"version\":\"2.5.5\"},\"performance\":{\"duration_ms\":1000},\"platform\":{\"arch\":\"ARM64\",\"os\":\"macOS\"}}},\"type\":\"analytics\"}}"
}

func testInitReportAnalyticsWorkflow(ctrl *gomock.Controller) error {
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes().Return(&workflow.EntryImpl{}, nil)
	return InitReportAnalyticsWorkflow(engine)
}

func testGetMockHTTPClient(t *testing.T, orgId string, requestPayload string, expectedPayload string) *http.Client {
	t.Helper()
	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/hidden/orgs/"+orgId+"/analytics?version=2024-03-07-experimental", req.URL.String())
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, err := io.ReadAll(req.Body)

		require.NoError(t, err)
		require.Equal(t, strings.TrimSpace(expectedPayload), string(body))

		return &http.Response{
			StatusCode: http.StatusCreated,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBufferString(requestPayload)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})
	return mockClient
}
