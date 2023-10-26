package localworkflows

import (
	"bytes"
	"fmt"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"
	"io"
	"net/http"
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
func reportAnalyticsEntrypoint(invocationCtx workflow.InvocationContext, inputData []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	logger.Println(reportAnalyticsWorkflowName + " workflow start")

	url := fmt.Sprintf("%s/rest/api/orgs/%s/analytics", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))

	for i, input := range inputData {
		logger.Println(fmt.Sprintf("%s: processing element %d", reportAnalyticsWorkflowName, i))
		documentLoader := gojsonschema.NewBytesLoader(input.GetPayload().([]byte))
		result, err := gojsonschema.Validate(scanDoneSchemaLoader, documentLoader)

		if err != nil {
			logger.Printf("Error validating input: %v\n", err)
			break
		}

		if !result.Valid() {
			return nil, fmt.Errorf("Error validating input: %v\n", result.Errors())
		}

		err = callEndpoint(invocationCtx, input, url)
		if err != nil {
			return nil, fmt.Errorf("Error calling endpoint: %v\n", err)
		}
	}
	return nil, err
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
