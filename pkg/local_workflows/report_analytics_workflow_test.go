package localworkflows

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"testing"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/golang/mock/gomock"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_shouldReportV2AnalyticsPayloadToApi(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(experimentalFlag, true)
	config.Set(configuration.INPUT_DIRECTORY, "/my/file")

	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	requestPayload := testGetAnalyticsV2PayloadString()
	mockClient := testGetMockHTTPClient(t, orgId, requestPayload)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_reportsHttpStatusError(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
	config := configuration.New()
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(configuration.INPUT_DIRECTORY, "/my/file")

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
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
	require.Error(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_reportsHttpError(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
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
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
	require.Error(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_validatesInput(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
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
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{input})
	require.Error(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_usesCLIInput(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
	config := configuration.New()
	requestPayload := testGetScanDonePayloadString()
	expectedPayload := testGetAnalyticsV2PayloadString()
	config.Set("inputData", requestPayload)
	orgId := "orgId"
	a := analytics.New()

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(experimentalFlag, true)

	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))
	mockClient := testGetMockHTTPClient(t, orgId, expectedPayload)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetAnalytics().Return(a).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1233.0"))).AnyTimes()
	engineMock.EXPECT().GetWorkflows().AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_validatesInputJson(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
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
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{input})
	require.Error(t, err)
}

func testPayload(payload string) workflow.Data {
	return workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName), "application/json", []byte(payload))
}

func testGetAnalyticsV2PayloadString() string {
	return fmt.Sprintf(`{
  "data": {
    "attributes": {
      "interaction": {
        "categories": [
          "oss",
          "test"
        ],
        "errors": [],
        "extension": {
          "device_id": "unique-uuid"
        },
        "id": "urn:snyk:interaction:8c846423-de44-4117-9d6d-2fca77f982a8",
        "results": [
          {
            "count": 15,
            "name": "critical"
          },
          {
            "count": 10,
            "name": "high"
          },
          {
            "count": 1,
            "name": "medium"
          },
          {
            "count": 2,
            "name": "low"
          }
        ],
        "stage": "dev",
        "status": "succeeded",
        "target": {
          "id": "pkg:filesystem/e83b663fb04548473ca1a80b622d17ddc1975b4323940afdaa4793576d9f7f60/file"
        },
        "timestamp_ms": 1693569600000,
        "type": "Scan done"
      },
      "runtime": {
        "application": {
          "name": "snyk-cli",
          "version": "1.1233.0"
        },
        "environment": {
          "name": "Pycharm",
          "version": "2023.1"
        },
        "integration": {
          "name": "IntelliJ",
          "version": "2.5.5"
        },
        "performance": {
          "duration_ms": 1000
        },
        "platform": {
          "arch": "%s",
          "os": "%s"
        }
      }
    },
    "type": "analytics"
  }
}`, runtime.GOARCH, runtime.GOOS)
}

func testGetScanDonePayloadString() string {
	return `{
		"data": {
			"type": "analytics",
			"attributes": {
				"path": "/my/file",
				"device_id": "unique-uuid",
				"application": "Pycharm",
				"application_version": "2023.1",
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

func testInitReportAnalyticsWorkflow(ctrl *gomock.Controller) error {
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes().Return(&workflow.EntryImpl{}, nil)
	return InitReportAnalyticsWorkflow(engine)
}

func testGetMockHTTPClient(t *testing.T, orgId string, requestPayload string) *http.Client {
	t.Helper()
	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/hidden/orgs/"+orgId+"/analytics?version=2024-03-07~experimental", req.URL.String())
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, err := io.ReadAll(req.Body)

		// used to replace whitespaces and uuids before comparing payloads
		expression := regexp.MustCompile(`\s|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

		require.NoError(t, err)
		require.Equal(t, expression.ReplaceAllString(requestPayload, ""), expression.ReplaceAllString(string(body), ""))

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
