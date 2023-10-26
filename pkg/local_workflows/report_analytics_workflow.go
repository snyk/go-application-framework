package localworkflows

import (
	"bytes"
	"fmt"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"io"
	"net/http"
	"time"
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

	url := fmt.Sprintf("%s/rest/api/orgs/%s/analytics", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION))

	for i, input := range inputData {
		logger.Println(fmt.Sprintf("%s: processing element %d", reportAnalyticsWorkflowName, i))
		err = callEndpoint(invocationCtx, input, url)
		if err != nil {
			break
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

type ScanDoneAnalyticsData struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			DeviceId                      string `json:"deviceId"`
			Application                   string `json:"application"`
			ApplicationVersion            string `json:"application_version"`
			Os                            string `json:"os"`
			Arch                          string `json:"arch"`
			IntegrationName               string `json:"integration_name"`
			IntegrationVersion            string `json:"integration_version"`
			IntegrationEnvironment        string `json:"integration_environment"`
			IntegrationEnvironmentVersion string `json:"integration_environment_version"`
			EventType                     string `json:"event_type"`
			Status                        string `json:"status"`
			ScanType                      string `json:"scan_type"`
			UniqueIssueCount              struct {
				Critical int `json:"critical"`
				High     int `json:"high"`
				Medium   int `json:"medium"`
				Low      int `json:"low"`
			} `json:"unique_issue_count"`
			DurationMs        string    `json:"duration_ms"`
			TimestampFinished time.Time `json:"timestamp_finished"`
		} `json:"attributes"`
	} `json:"data"`
}

func NewScanDoneAnalyticsData() *ScanDoneAnalyticsData {
	panic("not implemented")
}
