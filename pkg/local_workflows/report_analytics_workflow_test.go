package localworkflows

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/golang/mock/gomock"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_shouldReportToApi(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test: ", 0)
	config := configuration.New()
	orgID := "orgId"
	config.Set(configuration.ORGANIZATION, orgID)
	config.Set(experimentalFlag, true)
	config.Set(configuration.CACHE_PATH, t.TempDir())

	requestPayload := testGetScanDonePayloadString()

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	mockClient := testGetMockHTTPClient(t, orgID, requestPayload)

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
	orgID := "orgId"

	config.Set(configuration.ORGANIZATION, orgID)

	requestPayload := testGetScanDonePayloadString()

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	mockClient := newTestClient(func(req *http.Request) *http.Response {
		return &http.Response{
			// error code!
			StatusCode: 500,
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
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

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
	config.Set("inputData", requestPayload)
	orgId := "orgId"

	config.Set(configuration.ORGANIZATION, orgId)
	config.Set(experimentalFlag, true)

	// setup mocks
	ctrl := gomock.NewController(t)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))
	mockClient := testGetMockHTTPClient(t, orgId, requestPayload)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_validatesInputJson(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test:", 0)
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

func Test_ReportAnalytics_AppendToOutbox_InsertsIntoDatabase(t *testing.T) {
	conf := configuration.NewInMemory()
	conf.Set(configuration.CACHE_PATH, t.TempDir())
	ctrl := gomock.NewController(t)
	ctx := mocks.NewMockInvocationContext(ctrl)
	ctx.EXPECT().GetLogger().AnyTimes().Return(log.New(os.Stderr, "test:", 0))
	db, err := getReportAnalyticsOutboxDatabase(conf)
	require.NoError(t, err)

	id, err := appendToOutbox(ctx, db, []byte(testGetScanDonePayloadString()))

	require.NoError(t, err)
	require.Greater(t, len(id), 0)

	var payload []byte
	err = db.QueryRow("SELECT payload FROM outbox WHERE id = $1", id).Scan(&payload)
	require.NoError(t, err)
	require.Equal(t, testGetScanDonePayloadString(), string(payload))
}

func Test_ReportAnalytics_SendOutbox_shouldReportToApi(t *testing.T) {
	conf := configuration.NewInMemory()
	conf.Set(configuration.CACHE_PATH, t.TempDir())
	orgId := "orgId"
	conf.Set(configuration.ORGANIZATION, orgId)

	ctrl := gomock.NewController(t)
	ctx := mocks.NewMockInvocationContext(ctrl)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	ctx.EXPECT().GetLogger().AnyTimes().Return(log.New(os.Stderr, "test:", 0))
	ctx.EXPECT().GetConfiguration().AnyTimes().Return(conf)
	ctx.EXPECT().GetNetworkAccess().AnyTimes().Return(networkAccessMock)
	payloadString := testGetScanDonePayloadString()
	mockClient := testGetMockHTTPClient(t, orgId, payloadString)
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	db, err := getReportAnalyticsOutboxDatabase(conf)

	for i := 0; i < 5; i++ {
		_, err = appendToOutbox(ctx, db, []byte(payloadString))
		require.NoError(t, err)
	}

	err = sendOutbox(ctx, db)

	require.NoError(t, err)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM outbox").Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func testGetScanDonePayload(payload string) workflow.Data {
	return workflow.NewData(workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName), "application/json", []byte(payload))
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

func testInitReportAnalyticsWorkflow(ctrl *gomock.Controller) error {
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes().Return(&workflow.EntryImpl{}, nil)
	return InitReportAnalyticsWorkflow(engine)
}

func testGetMockHTTPClient(t *testing.T, orgId string, requestPayload string) *http.Client {
	mockClient := newTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/hidden/orgs/"+orgId+"/analytics?version=2023-11-09~experimental", req.URL.String())
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.Equal(t, requestPayload, string(body))

		return &http.Response{
			StatusCode: 201,
			// Send response to be tested
			Body: io.NopCloser(bytes.NewBufferString(requestPayload)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})
	return mockClient
}
