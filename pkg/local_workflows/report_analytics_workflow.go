package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var (
	WORKFLOWID_REPORT_ANALYTICS  workflow.Identifier = workflow.NewWorkflowIdentifier(reportAnalyticsWorkflowName)
	scanDoneSchemaLoader         gojsonschema.JSONLoader
	analyticsV2SchemaLoader      gojsonschema.JSONLoader
	reportAnalyticsWorkflowMutex sync.RWMutex = sync.RWMutex{}
)

const (
	reportAnalyticsWorkflowName      = "analytics.report"
	reportAnalyticsInputDataFlagName = "inputData"
	reportAnalyticsAPIVersion        = "2024-03-07~experimental"
)

// InitReportAnalyticsWorkflow initializes the reportAnalytics workflow before registering it with the engine.
func InitReportAnalyticsWorkflow(engine workflow.Engine) error {
	reportAnalyticsWorkflowMutex.Lock()
	defer reportAnalyticsWorkflowMutex.Unlock()
	// initialize workflow configuration
	params := pflag.NewFlagSet(reportAnalyticsWorkflowName, pflag.ExitOnError)
	params.StringP(reportAnalyticsInputDataFlagName, "i", "", "Input data containing scan done event")
	params.Bool(configuration.FLAG_EXPERIMENTAL, false, "enable experimental analytics report command")

	// load json schema for scan done event
	scanDoneSchemaLoader = gojsonschema.NewStringLoader(json_schemas.ScanDoneEventSchema)
	// load json schema for V2 analytics event
	analyticsV2SchemaLoader = gojsonschema.NewStringLoader(json_schemas.AnalyticsV2EventSchema)

	// register workflow with engine
	result, err := engine.Register(WORKFLOWID_REPORT_ANALYTICS, workflow.ConfigurationOptionsFromFlagset(params), reportAnalyticsEntrypoint)

	// don't display in help
	result.SetVisibility(false)
	return err
}

// reportAnalyticsEntrypoint is the entry point for the reportAnalytics workflow.
func reportAnalyticsEntrypoint(invocationCtx workflow.InvocationContext, inputData []workflow.Data) ([]workflow.Data, error) {
	reportAnalyticsWorkflowMutex.RLock()
	defer reportAnalyticsWorkflowMutex.RUnlock()

	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	if !config.GetBool(configuration.FLAG_EXPERIMENTAL) {
		return nil, fmt.Errorf("set `--experimental` flag to enable analytics report command")
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/analytics?version=%s", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION), reportAnalyticsAPIVersion)

	commandLineInput := config.GetString(reportAnalyticsInputDataFlagName)
	if commandLineInput != "" {
		logger.Printf("adding command line input")
		data := workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName),
			"application/json",
			[]byte(commandLineInput),
			workflow.WithLogger(logger),
		)
		inputData = append(inputData, data)
	}

	var err error
	for i, input := range inputData {
		logger.Printf("[%d] Processing element", i)

		payload, ok := input.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid payload type: %T", input.GetPayload())
		}

		version := 2
		documentLoader := gojsonschema.NewBytesLoader(payload)

		// check if payload is an analyticsV2 event
		result, validationErr := gojsonschema.Validate(analyticsV2SchemaLoader, documentLoader)

		if validationErr != nil {
			e := fmt.Errorf("analyticsV2Event error validating input at index %d: %w", i, validationErr)
			return nil, e
		}

		if !result.Valid() {
			// check if payload is a scanDone event (v1 analytics)
			result, validationErr = gojsonschema.Validate(scanDoneSchemaLoader, documentLoader)

			if validationErr != nil {
				e := fmt.Errorf("scanDoneEvent error validating input at index %d: %w", i, validationErr)
				return nil, e
			}

			if !result.Valid() {
				e := fmt.Errorf("scanDoneEvent at index: %d failed validation with errors: %v", i, result.Errors())
				return nil, e
			}

			version = 1
		}

		logger.Printf("[%d] Schema Version: %d", i, version)

		if version == 1 {
			// convert scanDoneEvent payload to AnalyticsV2 payload
			input, err = instrumentScanDoneEvent(invocationCtx, input)
			if err != nil {
				logger.Printf("Error converting v1 -> v2: %v\n", err)
				return nil, err
			}
		}

		logger.Printf("[%d] Data: %s", i, input.GetPayload())

		// send to V2 analytics endpoint
		callErr := callEndpoint(invocationCtx, input, url)
		if callErr != nil {
			err := fmt.Errorf("error calling endpoint for input at index %d: %w", i, callErr)
			return nil, err
		}
	}
	return nil, nil
}

func callEndpoint(invocationCtx workflow.InvocationContext, input workflow.Data, url string) error {
	// Create a request
	byteData, ok := input.GetPayload().([]byte)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", input.GetPayload())
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(byteData))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", input.GetContentType())

	// Send the request
	resp, err := invocationCtx.GetNetworkAccess().GetHttpClient().Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("error sending request: %v", resp.Status)
	}

	return nil
}

func instrumentScanDoneEvent(invocationCtx workflow.InvocationContext, input workflow.Data) (workflow.Data, error) {
	logger := invocationCtx.GetEnhancedLogger()
	config := invocationCtx.GetConfiguration()

	ic := analytics.NewInstrumentationCollector()
	ic.SetInteractionId(instrumentation.AssembleUrnFromUUID(uuid.NewString()))

	var scanDoneEvent json_schemas.ScanDoneEvent
	d, ok := input.GetPayload().([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type: %T", input.GetPayload())
	}

	err := json.Unmarshal(d, &scanDoneEvent)
	if err != nil {
		return nil, err
	}

	if len(scanDoneEvent.Data.Attributes.Path) > 0 {
		targetId, targetIdError := instrumentation.GetTargetId(scanDoneEvent.Data.Attributes.Path, instrumentation.AutoDetectedTargetId, instrumentation.WithConfiguredRepository(config))
		if targetIdError != nil {
			logger.Printf("Failed to derive target id, %v", targetIdError)
		}
		ic.SetTargetId(targetId)
	}

	// required v2 analytics parameters
	userAgent := networking.UserAgentInfo{
		App:                           invocationCtx.GetRuntimeInfo().GetName(),
		AppVersion:                    invocationCtx.GetRuntimeInfo().GetVersion(),
		Integration:                   scanDoneEvent.Data.Attributes.IntegrationName,
		IntegrationVersion:            scanDoneEvent.Data.Attributes.IntegrationVersion,
		IntegrationEnvironment:        scanDoneEvent.Data.Attributes.IntegrationEnvironment,
		IntegrationEnvironmentVersion: scanDoneEvent.Data.Attributes.IntegrationEnvironmentVersion,
		OS:                            runtime.GOOS,
		Arch:                          runtime.GOARCH,
	}
	ic.SetUserAgent(userAgent)
	ic.SetType(scanDoneEvent.Data.Type)
	ic.SetInteractionType(scanDoneEvent.Data.Attributes.EventType)
	ic.SetTimestamp(scanDoneEvent.Data.Attributes.TimestampFinished)
	duration, err := time.ParseDuration(scanDoneEvent.Data.Attributes.DurationMs + "ms")
	if err != nil {
		logger.Printf("Error parsing duration: %v\n", err)
	}
	ic.SetDuration(duration)
	ic.SetStatus(toStatus(scanDoneEvent.Data.Attributes.Status))

	// optional v2 analytics parameters
	categories := []string{
		instrumentation.ToProductCodename(scanDoneEvent.Data.Attributes.ScanType),
		"test",
	}
	ic.SetCategory(categories)
	ic.SetStage("dev")
	ic.SetTestSummary(toTestSummary(scanDoneEvent.Data.Attributes.UniqueIssueCount, scanDoneEvent.Data.Type))
	ic.AddExtension("device_id", scanDoneEvent.Data.Attributes.DeviceId)

	data, err := analytics.GetV2InstrumentationObject(ic, analytics.WithLogger(logger))
	if err != nil {
		return nil, err
	}

	v2InstrumentationData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	inputData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, "v2"),
		"application/json",
		v2InstrumentationData,
		workflow.WithLogger(logger),
	)

	return inputData, nil
}

func toTestSummary(uic json_schemas.UniqueIssueCount, t string) json_schemas.TestSummary {
	testSummary := json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{{
			Severity: "critical",
			Total:    uic.Critical,
			Open:     0,
			Ignored:  0,
		}, {
			Severity: "high",
			Total:    uic.High,
			Open:     0,
			Ignored:  0,
		}, {
			Severity: "medium",
			Total:    uic.Medium,
			Open:     0,
			Ignored:  0,
		}, {
			Severity: "low",
			Total:    uic.Low,
			Open:     0,
			Ignored:  0,
		}},
		Type: t,
	}
	return testSummary
}

func toStatus(s string) analytics.Status {
	sLC := strings.ToLower(s)
	// ScanDoneEvent does not enumerate valid statuses, so this is a best guess
	return analytics.Status(sLC)
}
