package localworkflows

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"
)

const reportAnalyticsWorkflowName = "reportAnalytics"

var WORKFLOWID_REPORT_ANALYTICS workflow.Identifier = workflow.NewWorkflowIdentifier(reportAnalyticsWorkflowName)

var scanDoneSchemaLoader gojsonschema.JSONLoader

// InitReportAnalyticsWorkflow initialises the reportAnalytics workflow before registering it with the engine.
func InitReportAnalyticsWorkflow(engine workflow.Engine) error {
	// initialise workflow configuration
	config := pflag.NewFlagSet(reportAnalyticsWorkflowName, pflag.ExitOnError)

	// load json schema for scan done event
	scanDoneSchemaLoader = gojsonschema.NewStringLoader(json_schemas.ScanDoneEventSchema)

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_REPORT_ANALYTICS, workflow.ConfigurationOptionsFromFlagset(config), reportAnalyticsEntrypoint)
	return err
}

// reportAnalyticsEntrypoint is the entry point for the reportAnalytics workflow.
func reportAnalyticsEntrypoint(invocationCtx workflow.InvocationContext, inputData []workflow.Data) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	logger.Println(reportAnalyticsWorkflowName + " workflow start")

	url := fmt.Sprintf("%s/rest/api/orgs/%s/analytics", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))

	for i, input := range inputData {
		logger.Printf(fmt.Sprintf("%s: processing element %d", reportAnalyticsWorkflowName, i))
		documentLoader := gojsonschema.NewBytesLoader(input.GetPayload().([]byte))
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
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(input.GetPayload().([]byte)))
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

	if resp.StatusCode != 201 {
		return fmt.Errorf("Error sending request: %v\n", resp.Status)
	}

	defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)
	return nil
}
