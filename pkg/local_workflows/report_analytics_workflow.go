package localworkflows

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"
)

var (
	WORKFLOWID_REPORT_ANALYTICS workflow.Identifier = workflow.NewWorkflowIdentifier(reportAnalyticsWorkflowName)

	scanDoneSchemaLoader gojsonschema.JSONLoader
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

	url := fmt.Sprintf("%s/hidden/orgs/%s/analytics?version=2023-11-09~experimental", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))

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
		result, validationErr := gojsonschema.Validate(scanDoneSchemaLoader, documentLoader)

		if validationErr != nil {
			err := fmt.Errorf("error validating input at index %d: %w", i, validationErr)
			return nil, err
		}

		if !result.Valid() {
			err := fmt.Errorf("validation failed for input at index %d: %v", i, result.Errors())
			return nil, err
		}

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
