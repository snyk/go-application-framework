package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/networking"
	"net/http"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"
)

var (
	WORKFLOWID_REPORT_ANALYTICS workflow.Identifier = workflow.NewWorkflowIdentifier(reportAnalyticsWorkflowName)

	scanDoneSchemaLoader    gojsonschema.JSONLoader
	analyticsV2SchemaLoader gojsonschema.JSONLoader
)

const (
	reportAnalyticsWorkflowName      = "analytics.report"
	reportAnalyticsInputDataFlagName = "inputData"
	reportAnalyticsAPIVersion        = "2024-03-07~experimental"
)

// InitReportAnalyticsWorkflow initializes the reportAnalytics workflow before registering it with the engine.
func InitReportAnalyticsWorkflow(engine workflow.Engine) error {
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
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()

	logger.Println(reportAnalyticsWorkflowName + " workflow start")

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
		)
		inputData = append(inputData, data)
	}

	var err error
	for i, input := range inputData {
		logger.Printf(fmt.Sprintf("processing element %d", i))
		payload, ok := input.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid payload type: %T", input.GetPayload())
		}

		documentLoader := gojsonschema.NewBytesLoader(payload)

		// check if payload is an analyticsV2 event
		logger.Print("validating analyticsV2Event")
		result, validationErr := gojsonschema.Validate(analyticsV2SchemaLoader, documentLoader)

		if validationErr != nil {
			e := fmt.Errorf("analyticsV2Event error validating input at index %d: %w", i, validationErr)
			return nil, e
		}

		if !result.Valid() {
			logger.Print("analyticsV2Event validation failed")
			logger.Print("validating scanDoneEvent")

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

			// convert scanDoneEvent payload to AnalyticsV2 payload
			err = instrumentScanDoneEvent(invocationCtx, input)
			if err != nil {
				return nil, err
			}
			return nil, nil
		}

		// send to V2 analytics endpoint
		callErr := callEndpoint(invocationCtx, input, url)
		if callErr != nil {
			err := fmt.Errorf("error calling endpoint for input at index %d: %w", i, callErr)
			return nil, err
		}
	}
	logger.Println(reportAnalyticsWorkflowName + " workflow end")
	return nil, nil
}

func callEndpoint(invocationCtx workflow.InvocationContext, input workflow.Data, url string) error {
	// Create a request
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(input.GetPayload().([]byte)))
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

func instrumentScanDoneEvent(invocationCtx workflow.InvocationContext, input workflow.Data) error {
	logger := invocationCtx.GetLogger()
	a := invocationCtx.GetAnalytics()
	ic := a.GetInstrumentation()

	var scanDoneEvent json_schemas.ScanDoneEvent
	d, ok := input.GetPayload().([]byte)
	if !ok {
		return fmt.Errorf("invalid payload type: %T", input.GetPayload())
	}

	err := json.Unmarshal(d, &scanDoneEvent)
	if err != nil {
		logger.Printf("Error unmarshalling json: %v\n", err)
		return err
	}

	// required v2 analytics parameters
	userAgent := networking.UserAgentInfo{
		App:                           scanDoneEvent.Data.Attributes.Application,
		AppVersion:                    scanDoneEvent.Data.Attributes.ApplicationVersion,
		Integration:                   scanDoneEvent.Data.Attributes.IntegrationName,
		IntegrationVersion:            scanDoneEvent.Data.Attributes.IntegrationVersion,
		IntegrationEnvironment:        scanDoneEvent.Data.Attributes.IntegrationEnvironment,
		IntegrationEnvironmentVersion: scanDoneEvent.Data.Attributes.IntegrationEnvironmentVersion,
		OS:                            scanDoneEvent.Data.Attributes.Os,
		Arch:                          scanDoneEvent.Data.Attributes.Arch,
	}
	ic.SetUserAgent(userAgent)
	ic.SetType(scanDoneEvent.Data.Type)
	// TODO: eventType needs to be converted correctly (Knut knows)
	ic.SetInteractionType(scanDoneEvent.Data.Attributes.EventType)
	ic.SetTimestamp(scanDoneEvent.Data.Attributes.TimestampFinished)
	duration, err := time.ParseDuration(scanDoneEvent.Data.Attributes.DurationMs + "ms")
	if err != nil {
		logger.Printf("Error parsing duration: %v\n", err)
	}
	ic.SetDuration(duration)
	ic.SetStatus(toStatus(scanDoneEvent.Data.Attributes.Status))

	// optional v2 analytics parameters
	ic.SetCategory([]string{scanDoneEvent.Data.Attributes.ScanType, "test"})
	ic.SetStage("dev")
	ic.SetTestSummary(toTestSummary(scanDoneEvent.Data.Attributes.UniqueIssueCount, scanDoneEvent.Data.Type))

	return nil
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

func toStatus(status string) analytics.Status {
	if status == "success" {
		return analytics.Success
	}
	return analytics.Failure
}
