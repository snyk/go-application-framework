package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"io"
	"net/http"
)

const reportAnalyticsWorkflowName = "reportAnalytics"

var WORKFLOWID_REPORT_ANALYTICS workflow.Identifier = workflow.NewWorkflowIdentifier(reportAnalyticsWorkflowName)

// InitReportAnalyticsWorkflow initialises the whoAmI workflow before registering it with the engine.
func InitReportAnalyticsWorkflow(engine workflow.Engine) error {
	// initialise workflow configuration
	config := pflag.NewFlagSet(reportAnalyticsWorkflowName, pflag.ExitOnError)
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

	url := fmt.Sprintf("%s/rest/%s/analytics", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))

	for i, input := range inputData {
		logger.Println(fmt.Sprintf("%s: processing element %d", reportAnalyticsWorkflowName, i))
		err = callEndpoint(invocationCtx, input, url)
	}
	return []workflow.Data{}, err
}

func callEndpoint(invocationCtx workflow.InvocationContext, input workflow.Data, url string) error {
	logger := invocationCtx.GetLogger()
	// Marshal the payload to JSON
	payloadBytes, err := json.Marshal(input.GetPayload())
	if err != nil {
		logger.Printf("Error marshaling payload: %v\n", err)
		return err
	}

	// Create a request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
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
