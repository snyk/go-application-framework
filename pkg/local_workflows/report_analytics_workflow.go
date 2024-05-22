package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/internal/api/clients"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/utils"
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
	instrumentationCollector := invocationCtx.GetAnalytics().GetInstrumentation()

	logger.Println(reportAnalyticsWorkflowName + " workflow start")

	if !config.GetBool(configuration.FLAG_EXPERIMENTAL) {
		return nil, fmt.Errorf("set `--experimental` flag to enable analytics report command")
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/analytics?version=2024-03-07-experimental", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))

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

	for i, input := range inputData {
		logger.Printf(fmt.Sprintf("processing element %d", i))
		payload, ok := input.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid payload type: %T", input.GetPayload())
		}

		documentLoader := gojsonschema.NewBytesLoader(payload)

		// check if payload is an analytics v2 event
		result, validationErr := gojsonschema.Validate(analyticsV2SchemaLoader, documentLoader)

		if validationErr != nil {
			err := fmt.Errorf("error validating input at index %d: %w", i, validationErr)
			return nil, err
		}

		if !result.Valid() {
			// check if payload is a scanDone event (v1 analytics)
			result, validationErr = gojsonschema.Validate(scanDoneSchemaLoader, documentLoader)

			if validationErr != nil {
				err := fmt.Errorf("error validating input at index %d: %w", i, validationErr)
				return nil, err
			}

			if !result.Valid() {
				err := fmt.Errorf("validation failed for input at index %d: %v", i, result.Errors())
				return nil, err
			}

			// convert analytics payload to instrumentation payload
			err := instrumentScanDoneEvent(invocationCtx, &instrumentationCollector, input)
			if err != nil {
				return nil, err
			}
		}

		// TODO: send instrumentation payload to V2 analytics endpoint
		callErr := callEndpoint(invocationCtx, input, url)
		if callErr != nil {
			err := fmt.Errorf("error calling endpoint for input at index %d: %w", i, callErr)
			return nil, err
		}
	}
	logger.Println(reportAnalyticsWorkflowName + " workflow end")
	return nil, nil
}

func instrumentScanDoneEvent(invocationCtx workflow.InvocationContext, ic *analytics.InstrumentationCollector, input workflow.Data) error {
	collector := *ic
	logger := invocationCtx.GetLogger()

	var scanDoneEvent json_schemas.ScanDoneEvent
	d := input.GetPayload().([]byte)

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
		IntegrationEnvironmentVersion: scanDoneEvent.Data.Attributes.IntegrationEnvironmentVersion,
		OS:                            scanDoneEvent.Data.Attributes.Os,
		Arch:                          scanDoneEvent.Data.Attributes.Arch,
	}
	collector.SetUserAgent(userAgent)
	collector.SetType(scanDoneEvent.Data.Type)
	collector.SetTimestamp(scanDoneEvent.Data.Attributes.TimestampFinished)
	durationMs, err := time.ParseDuration(scanDoneEvent.Data.Attributes.DurationMs)
	if err != nil {
		logger.Printf("Error parsing durationMs: %v\n", err)
	}
	collector.SetDuration(durationMs)
	// TODO: figure out what the scan event statuses are and map to v2 analytics event accordingly
	collector.SetStatus(toStatus(scanDoneEvent.Data.Attributes.Status))
	// TODO: figure out what this is in the scan done event - should be in urn format
	//collector.SetInteractionId()
	// TODO: figure out what this is in the scan done event - should be in purl format
	//collector.SetTargetId()

	// optional v2 analytics parameters
	collector.SetCategory([]string{scanDoneEvent.Data.Attributes.ScanType})
	// stage does not exist in scan done event
	// collector.SetStage()
	// errors do not exist in scan done event
	//collector.AddError()
	// extension does not exist in scan done event
	//collector.AddExtension()
	// TODO: figure out what this is in the scan done event - maybe UniqueIssueCount?
	//collector.SetTestSummary()

	return nil
}

func toStatus(status string) analytics.Status {
	if status == "success" {
		return analytics.Success
	}
	return analytics.Failure
}

func instrumentAnalyticsV2Event(invocationCtx workflow.InvocationContext, ic *analytics.InstrumentationCollector, input workflow.Data) error {
	return nil
}

func callEndpoint(invocationCtx workflow.InvocationContext, input workflow.Data, url string) error {
	logger := invocationCtx.GetLogger()

	// Create a request
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(input.GetPayload().([]byte)))
	if err != nil {
		logger.Printf("Error creating request: %v\n", err)
		return err
	}
	req.Header.Set("Content-Type", input.GetContentType())

	// Send the request

	resp, err := invocationCtx.GetNetworkAccess().GetHttpClient().Do(req)
	if err != nil {
		logger.Printf("Error sending request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("error sending request: %v", resp.Status)
	}

	return nil
}

func callEndpoint2(invocationCtx workflow.InvocationContext, ic *analytics.InstrumentationCollector) error {
	logger := invocationCtx.GetLogger()

	// create request
	req := createInstrumentationRequest(invocationCtx, ic)

	// send request
	response, err := invocationCtx.GetNetworkAccess().GetHttpClient().Do(req)
	if err != nil {
		logger.Printf("Error sending request: %v\n", err)
	}
	defer response.Body.Close()
	logger.Printf("analytics v2 response: %v\n", response)

	return nil
}

func createInstrumentationRequest(invocationCtx workflow.InvocationContext, ic *analytics.InstrumentationCollector) *http.Request {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()

	instrumentationCollector := *ic
	d, err := analytics.GetV2InstrumentationObject(instrumentationCollector)
	if err != nil {
		logger.Printf("Error getting v2 instrumentation object: %v\n", err)
		return nil
	}

	request, err := clients.NewCreateAnalyticsRequest(config.GetString(configuration.API_URL), utils.ValueOf(uuid.Parse(config.GetString(configuration.ORGANIZATION))), &clients.CreateAnalyticsParams{Version: "2024-03-07-experimental"}, *d)
	if err != nil {
		logger.Printf("Error creating request: %v\n", err)
		return nil
	}

	return request
}
