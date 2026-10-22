package localworkflows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	api "github.com/snyk/go-application-framework/internal/api/analytics/2024-10-15"
	"github.com/snyk/go-application-framework/internal/osname"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const testOrgID = "orgId"

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_shouldReportV2AnalyticsPayloadToApi(t *testing.T) {
	// setup
	logger := zerolog.New(io.Discard)
	config := configuration.New()

	config.Set(configuration.ORGANIZATION, testOrgID)
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	config.Set(configuration.INPUT_DIRECTORY, "/my/file")

	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))

	requestPayload := testGetAnalyticsV2PayloadString()
	mockClient := testGetMockHTTPClient(t, testEnriched(requestPayload, testDefaultPlatformConfiguration))

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(nil).AnyTimes()
	invocationContextMock.EXPECT().Context().Return(t.Context()).AnyTimes()
	networkAccessMock.EXPECT().GetHttpClient().Return(mockClient).AnyTimes()

	_, err := reportAnalyticsEntrypoint(invocationContextMock, []workflow.Data{testPayload(requestPayload)})
	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_withholdsMachineId(t *testing.T) {
	tests := map[string]string{
		"v2 input":                   testGetAnalyticsV2PayloadString(),
		"v1 scan-done input":         testGetScanDonePayloadString(),
		"machine id of the producer": testWithMachineID(testGetAnalyticsV2PayloadString(), "producer-machine-id"),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ri := mocks.NewMockRuntimeInfo(ctrl)
			ri.EXPECT().GetName().Return("snyk-cli").AnyTimes()
			ri.EXPECT().GetVersion().Return("1.1233.0").AnyTimes()
			ri.EXPECT().GetMachineID().Return("test-machine-id", nil).Times(0)
			expected := testEnriched(testGetAnalyticsV2PayloadString(), testDefaultPlatformConfiguration)
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), ri)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
		})
	}
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_sendsNoMachineKeysInRuntime(t *testing.T) {
	tests := map[string]string{
		"v2 input":                       testGetAnalyticsV2PayloadString(),
		"v1 scan-done input":             testGetScanDonePayloadString(),
		"machine id of the producer":     testWithMachineID(testGetAnalyticsV2PayloadString(), "producer-machine-id"),
		"nested machine of the producer": strings.Replace(testGetAnalyticsV2PayloadString(), `"performance"`, `"machine": {"id": "producer-machine-id"}, "performance"`, 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ri := mocks.NewMockRuntimeInfo(ctrl)
			ri.EXPECT().GetName().Return("snyk-cli").AnyTimes()
			ri.EXPECT().GetVersion().Return("1.1233.0").AnyTimes()
			ri.EXPECT().GetMachineID().Return("test-machine-id", nil).Times(0)
			var sent []byte
			client := testutils.NewTestClient(func(req *http.Request) *http.Response {
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				sent = body
				return &http.Response{StatusCode: http.StatusCreated, Body: http.NoBody, Header: make(http.Header)}
			})
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, client, ri)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
			var body struct {
				Data struct {
					Attributes struct {
						Runtime map[string]any `json:"runtime"`
					} `json:"attributes"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(sent, &body))
			require.NotEmpty(t, body.Data.Attributes.Runtime)
			require.NotContains(t, body.Data.Attributes.Runtime, "machine")
			require.NotContains(t, body.Data.Attributes.Runtime, "machine_id")
		})
	}
}

func Test_ReportAnalytics_addMachineID(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.New(io.Discard)
	machineIDSource := func(id string, err error) runtimeinfo.RuntimeInfo {
		ri := mocks.NewMockRuntimeInfo(ctrl)
		ri.EXPECT().GetMachineID().Return(id, err).AnyTimes()
		return ri
	}
	tests := map[string]struct {
		machineID *string
		ri        runtimeinfo.RuntimeInfo
		expected  *string
	}{
		"sets the machine id":                  {ri: machineIDSource("test-machine-id", nil), expected: new("test-machine-id")},
		"keeps the machine id of the producer": {machineID: new("producer-machine-id"), ri: machineIDSource("test-machine-id", nil), expected: new("producer-machine-id")},
		"no runtime info":                      {ri: nil, expected: nil},
		"no stable machine id":                 {ri: machineIDSource("", runtimeinfo.ErrNoMachineID), expected: nil},
		"error reading the machine id":         {ri: machineIDSource("", errors.New("read failed")), expected: nil},
		"usable machine id with an error":      {ri: machineIDSource("test-machine-id", errors.New("read failed")), expected: new("test-machine-id")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rt := &api.Runtime{MachineId: tc.machineID}

			addMachineID(rt, tc.ri, &logger)

			require.Equal(t, tc.expected, rt.MachineId)
		})
	}
}

func Test_ReportAnalytics_addMachineID_encodesAFlatMachineId(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.New(io.Discard)
	ri := mocks.NewMockRuntimeInfo(ctrl)
	ri.EXPECT().GetMachineID().Return("test-machine-id", nil)
	rt := &api.Runtime{}

	addMachineID(rt, ri, &logger)

	encoded, err := json.Marshal(rt)
	require.NoError(t, err)
	require.JSONEq(t, `{"machine_id": "test-machine-id"}`, string(encoded))
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_addsPlatformConfiguration(t *testing.T) {
	tests := map[string]string{
		"v2 input":           testGetAnalyticsV2PayloadString(),
		"v1 scan-done input": testGetScanDonePayloadString(),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			testSetProxyEnvironment(t, map[string]string{"HTTPS_PROXY": "http://proxy.example.com:8080"})
			expected := testEnriched(testGetAnalyticsV2PayloadString(), testConfiguredPlatformConfiguration)
			ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1233.0"))
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), ri)
			testConfigureNetwork(invocationCtx.GetConfiguration())

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
		})
	}
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_keepsPlatformConfigurationOfTheProducer(t *testing.T) {
	ctrl := gomock.NewController(t)
	testSetProxyEnvironment(t, map[string]string{"HTTPS_PROXY": "http://proxy.example.com:8080"})
	payload := testWithPlatformConfiguration(testGetAnalyticsV2PayloadString(), `{"insecure_https": false}`)
	expected := testEnriched(testGetAnalyticsV2PayloadString(),
		`{"extra_ca_certs": true, "fips": true, "insecure_https": false, "network_request_attempts": 3, "proxy": true}`)
	invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), nil)
	testConfigureNetwork(invocationCtx.GetConfiguration())

	_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_addsPlatformWhenMissing(t *testing.T) {
	interaction := `"interaction": {"id": "urn:snyk:interaction:8c846423-de44-4117-9d6d-2fca77f982a8", "status": "succeeded",
		"target": {"id": "pkg:filesystem/abc/file"}, "timestamp_ms": 1693569600000, "type": "Scan done"}`
	platform := testWithOSName(fmt.Sprintf(`"platform": {"arch": "%s", "configuration": %s, "os": "%s"}`, runtime.GOARCH, testDefaultPlatformConfiguration, runtime.GOOS))
	tests := map[string]struct {
		attributes string
		expected   string
	}{
		"no runtime": {
			attributes: interaction,
			expected:   interaction + `, "runtime": {` + platform + `}`,
		},
		"runtime without platform": {
			attributes: interaction + `, "runtime": {"application": {"name": "snyk-ls", "version": "1.0.0"}}`,
			expected:   interaction + `, "runtime": {"application": {"name": "snyk-ls", "version": "1.0.0"}, ` + platform + `}`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			payload := `{"data": {"type": "analytics", "attributes": {` + tc.attributes + `}}}`
			expected := `{"data": {"attributes": {` + tc.expected + `}, "type": "analytics"}}`
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), nil)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
		})
	}
}

func Test_ReportAnalytics_addOSName(t *testing.T) {
	tests := map[string]struct {
		osname   *string
		detected string
		expected *string
	}{
		"sets the detected name":         {detected: "macOS 15.1", expected: new("macOS 15.1")},
		"keeps the name of the producer": {osname: new("Ubuntu 22.04.4 LTS"), detected: "macOS 15.1", expected: new("Ubuntu 22.04.4 LTS")},
		"leaves out an undetected name":  {detected: "", expected: nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			platform := &api.Platform{Os: "darwin", Arch: "arm64", Osname: tc.osname}

			addOSName(platform, tc.detected)

			require.Equal(t, tc.expected, platform.Osname)
		})
	}
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_addsOSName(t *testing.T) {
	tests := map[string]string{
		"v2 input":           testGetAnalyticsV2PayloadString(),
		"v1 scan-done input": testGetScanDonePayloadString(),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1233.0"))
			expected := testEnriched(testGetAnalyticsV2PayloadString(), testDefaultPlatformConfiguration)
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), ri)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
		})
	}
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_keepsOSNameAndPersonaOfTheProducer(t *testing.T) {
	ctrl := gomock.NewController(t)
	payload := strings.Replace(testGetAnalyticsV2PayloadString(), `"os": "`+runtime.GOOS+`"`, `"os": "`+runtime.GOOS+`", "osname": "Plan 9 4"`, 1)
	payload = strings.Replace(payload, `"results":`,
		`"persona": {"agent": "claude_code", "agent_version": "2.1.233", "interactive": false, "interactive_mode": "6"}, "results":`, 1)
	expected := testWithPlatformConfiguration(payload, testDefaultPlatformConfiguration)
	invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), nil)

	_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_reportsWhetherTheEnvironmentProxiesTheAPI(t *testing.T) {
	const proxyURL = "http://proxy.example.com:8080"
	tests := map[string]struct {
		apiURL string
		env    map[string]string
		proxy  string
	}{
		"no proxy":              {env: nil, proxy: `, "proxy": false`},
		"HTTPS_PROXY":           {env: map[string]string{"HTTPS_PROXY": proxyURL}, proxy: `, "proxy": true`},
		"lowercase https_proxy": {env: map[string]string{"https_proxy": proxyURL}, proxy: `, "proxy": true`},
		"HTTP_PROXY does not apply to an https API": {env: map[string]string{"HTTP_PROXY": proxyURL}, proxy: `, "proxy": false`},
		"NO_PROXY lists the API host":               {env: map[string]string{"HTTPS_PROXY": proxyURL, "NO_PROXY": "api.snyk.io"}, proxy: `, "proxy": false`},
		"NO_PROXY lists another host":               {env: map[string]string{"HTTPS_PROXY": proxyURL, "NO_PROXY": "example.com"}, proxy: `, "proxy": true`},
		"unparsable proxy URL is not used":          {env: map[string]string{"HTTPS_PROXY": "http://%zz"}, proxy: `, "proxy": false`},
		"undeterminable proxy is left out": {
			apiURL: "http://api.snyk.io",
			env:    map[string]string{"HTTP_PROXY": proxyURL, "REQUEST_METHOD": "GET"},
			proxy:  ``,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			testSetProxyEnvironment(t, tc.env)
			apiURL := tc.apiURL
			if apiURL == "" {
				apiURL = "https://api.snyk.io"
			}
			payload := testGetAnalyticsV2PayloadString()
			expected := testEnriched(payload, `{"extra_ca_certs": false, "fips": false, "insecure_https": false, "network_request_attempts": 1`+tc.proxy+`}`)
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), nil)
			invocationCtx.GetConfiguration().Set(configuration.API_URL, apiURL)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
		})
	}
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_reportsExtraCaCertsOnlyForANonEmptyCaFile(t *testing.T) {
	tests := map[string]struct {
		caFile       string
		extraCaCerts bool
	}{
		"empty CA file": {caFile: "", extraCaCerts: false},
		"CA file set":   {caFile: "/certs/extra-ca.pem", extraCaCerts: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			payload := testGetAnalyticsV2PayloadString()
			expected := testEnriched(payload,
				fmt.Sprintf(`{"extra_ca_certs": %t, "fips": false, "insecure_https": false, "network_request_attempts": 1, "proxy": false}`, tc.extraCaCerts))
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), nil)
			invocationCtx.GetConfiguration().Set(configuration.ADD_TRUSTED_CA_FILE, tc.caFile)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.NoError(t, err)
		})
	}
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_keepsNumbersInExtensionAndResultsExact(t *testing.T) {
	ctrl := gomock.NewController(t)
	payload := strings.Replace(testGetAnalyticsV2PayloadString(),
		`"device_id": "unique-uuid"`,
		`"device_id": "unique-uuid", "large": 9007199254740993, "larger": 12345678901234567890, "ratio": 1.50`, 1)
	payload = strings.Replace(payload, `"count": 15,`, `"count": 9007199254740993,`, 1)
	invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, testEnriched(payload, testDefaultPlatformConfiguration)), nil)

	_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_sendsUndecodableInputUnchanged(t *testing.T) {
	ctrl := gomock.NewController(t)
	ri := mocks.NewMockRuntimeInfo(ctrl)
	ri.EXPECT().GetMachineID().Return("test-machine-id", nil).Times(0)
	payload := testGetUndecodableAnalyticsV2PayloadString()
	invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, payload), ri)

	_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_removesMachineIdFromUndecodableInput(t *testing.T) {
	ctrl := gomock.NewController(t)
	expected := testGetUndecodableAnalyticsV2PayloadString()
	payload := testWithMachineID(expected, "producer-machine-id")
	invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, testGetMockHTTPClient(t, expected), nil)

	_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

	require.NoError(t, err)
}

func Test_ReportAnalytics_ReportAnalyticsEntryPoint_rejectsInvalidInput(t *testing.T) {
	tests := map[string]string{
		"empty object":                         `{}`,
		"not json":                             ``,
		"machine id not string":                strings.Replace(testGetAnalyticsV2PayloadString(), `"performance"`, `"machine_id": 5, "performance"`, 1),
		"platform configuration is not object": testWithPlatformConfiguration(testGetAnalyticsV2PayloadString(), `5`),
		"proxy not boolean":                    testWithPlatformConfiguration(testGetAnalyticsV2PayloadString(), `{"proxy": "yes"}`),
		"network request attempts not integer": testWithPlatformConfiguration(testGetAnalyticsV2PayloadString(), `{"network_request_attempts": 1.5}`),
		"osname not string":                    strings.Replace(testGetAnalyticsV2PayloadString(), `"os":`, `"osname": 15, "os":`, 1),
		"persona not object":                   strings.Replace(testGetAnalyticsV2PayloadString(), `"results":`, `"persona": "claude_code", "results":`, 1),
		"persona interactive mode not string":  strings.Replace(testGetAnalyticsV2PayloadString(), `"results":`, `"persona": {"interactive_mode": 6}, "results":`, 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := testutils.NewTestClient(func(req *http.Request) *http.Response {
				t.Errorf("unexpected request to %s", req.URL)
				return &http.Response{StatusCode: http.StatusCreated, Body: http.NoBody, Header: make(http.Header)}
			})
			invocationCtx := testReportAnalyticsInvocationContext(t, ctrl, client, nil)

			_, err := reportAnalyticsEntrypoint(invocationCtx, []workflow.Data{testPayload(payload)})

			require.Error(t, err)
		})
	}
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

	mockClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
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
	invocationContextMock.EXPECT().Context().Return(t.Context()).AnyTimes()
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

	mockClient := testutils.NewErrorProducingTestClient(func(req *http.Request) *http.Response { return nil })

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().Context().Return(t.Context()).AnyTimes()
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
	expectedPayload := testGetAnalyticsV2PayloadString()
	config.Set("inputData", expectedPayload)
	a := analytics.New()

	config.Set(configuration.ORGANIZATION, testOrgID)
	config.Set(configuration.FLAG_EXPERIMENTAL, true)

	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))
	mockClient := testGetMockHTTPClient(t, testEnriched(expectedPayload, testDefaultPlatformConfiguration))

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetAnalytics().Return(a).AnyTimes()
	invocationContextMock.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.1233.0"))).AnyTimes()
	invocationContextMock.EXPECT().Context().Return(t.Context()).AnyTimes()
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

// testGetUndecodableAnalyticsV2PayloadString is valid against the schema, but overflows the int64 duration of the request body type.
func testGetUndecodableAnalyticsV2PayloadString() string {
	return strings.Replace(testGetAnalyticsV2PayloadString(), `"duration_ms": 1000`, `"duration_ms": 99999999999999999999`, 1)
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

func testGetMockHTTPClient(t *testing.T, requestPayload string) *http.Client {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t)
	mockClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		// Test request parameters
		require.Equal(t, "/hidden/orgs/"+testOrgID+"/analytics?version=2024-10-15", req.URL.RequestURI())
		require.Equal(t, "POST", req.Method)
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, err := io.ReadAll(req.Body)

		// used to replace whitespaces, uuids and path hashes before comparing payloads; the hash of a target path differs by OS
		expression := regexp.MustCompile(`\s|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{64}`)

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

func testReportAnalyticsInvocationContext(t *testing.T, ctrl *gomock.Controller, client *http.Client, ri runtimeinfo.RuntimeInfo) *mocks.MockInvocationContext {
	t.Helper()
	require.NoError(t, testInitReportAnalyticsWorkflow(ctrl))
	logger := zerolog.New(io.Discard)
	config := configuration.New()
	config.Set(configuration.ORGANIZATION, testOrgID)
	config.Set(configuration.FLAG_EXPERIMENTAL, true)

	networkAccessMock := mocks.NewMockNetworkAccess(ctrl)
	networkAccessMock.EXPECT().GetHttpClient().Return(client).AnyTimes()
	invocationCtx := mocks.NewMockInvocationContext(ctrl)
	invocationCtx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationCtx.EXPECT().GetNetworkAccess().Return(networkAccessMock).AnyTimes()
	invocationCtx.EXPECT().GetRuntimeInfo().Return(ri).AnyTimes()
	invocationCtx.EXPECT().Context().Return(t.Context()).AnyTimes()
	return invocationCtx
}

// testWithMachineID returns the v2 payload with runtime.machine_id set, in the key order the workflow encodes it.
func testWithMachineID(payload string, machineID string) string {
	return strings.Replace(payload, `"performance"`, `"machine_id": "`+machineID+`", "performance"`, 1)
}

const (
	// a bare configuration has no API URL to proxy and no attempt count, which the retry middleware treats as one attempt
	testDefaultPlatformConfiguration    = `{"extra_ca_certs": false, "fips": false, "insecure_https": false, "network_request_attempts": 1, "proxy": false}`
	testConfiguredPlatformConfiguration = `{"extra_ca_certs": true, "fips": true, "insecure_https": true, "network_request_attempts": 3, "proxy": true}`
)

// testWithPlatformConfiguration returns the v2 payload with runtime.platform.configuration set, in the key order the workflow encodes it.
func testWithPlatformConfiguration(payload string, platformConfiguration string) string {
	return strings.Replace(payload, `"os":`, `"configuration": `+platformConfiguration+`, "os":`, 1)
}

// testEnriched returns the v2 payload as the workflow sends it: with the platform configuration and the detected operating system name.
func testEnriched(payload string, platformConfiguration string) string {
	return testWithOSName(testWithPlatformConfiguration(payload, platformConfiguration))
}

// testWithOSName returns the v2 payload with runtime.platform.osname set to the detected name, in the key order the workflow encodes it.
func testWithOSName(payload string) string {
	name := osname.Get()
	if name == "" {
		return payload
	}
	encoded, _ := json.Marshal(name) //nolint:errcheck // marshaling a string can't fail
	return strings.Replace(payload, `"os": "`+runtime.GOOS+`"`, `"os": "`+runtime.GOOS+`", "osname": `+string(encoded), 1)
}

func testConfigureNetwork(config configuration.Configuration) {
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.INSECURE_HTTPS, true)
	config.Set(configuration.FIPS_ENABLED, true)
	config.Set(middleware.ConfigurationKeyRequestAttempts, 3)
	config.Set(configuration.ADD_TRUSTED_CA_FILE, "/certs/extra-ca.pem")
}

// testSetProxyEnvironment clears every variable the proxy rules read, in both cases, before setting env.
func testSetProxyEnvironment(t *testing.T, env map[string]string) {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t, "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD")
	for key, value := range env {
		t.Setenv(key, value)
	}
}
