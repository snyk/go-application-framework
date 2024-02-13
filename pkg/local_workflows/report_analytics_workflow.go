package localworkflows

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/xeipuuv/gojsonschema"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/local_workflows/reportanalytics"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

//goland:noinspection GoVarAndConstTypeMayBeOmitted
var (
	// WORKFLOWID_REPORT_ANALYTICS is the identifier for the reportAnalytics workflow.
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
	if err != nil {
		return errors.Wrap(err, "failed to register report analytics workflow")
	}

	// don't display in help
	result.SetVisibility(false)
	return nil
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

	const jsonContentType = "application/json"
	commandLineInput := config.GetString(reportAnalyticsInputDataFlagName)
	if commandLineInput != "" {
		logger.Printf("adding command line input")
		data := workflow.NewData(
			workflow.NewTypeIdentifier(WORKFLOWID_REPORT_ANALYTICS, reportAnalyticsWorkflowName),
			jsonContentType,
			[]byte(commandLineInput),
		)
		inputData = append(inputData, data)
	}
	db, err := reportanalytics.GetReportAnalyticsOutboxDatabase(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get report analytics database")
	}

	for i, input := range inputData {
		logger.Printf(fmt.Sprintf("processing element %d", i))
		payload, ok := input.GetPayload().([]byte)
		if !ok {
			return nil, errors.New("input payload is not a byte array")
		}
		documentLoader := gojsonschema.NewBytesLoader(payload)
		result, validationErr := gojsonschema.Validate(scanDoneSchemaLoader, documentLoader)

		if validationErr != nil {
			err = fmt.Errorf("error validating input at index %d: %w", i, validationErr)
			return nil, err
		}

		if !result.Valid() {
			err = fmt.Errorf("validation failed for input at index %d: %v", i, result.Errors())
			return nil, err
		}

		_, err = reportanalytics.AppendToOutbox(invocationCtx, db, payload)
		if err != nil {
			return nil, errors.Wrap(err, "failed to append to outbox")
		}
	}

	err = reportanalytics.SendOutbox(invocationCtx, db, jsonContentType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send outbox")
	}
	logger.Println(reportAnalyticsWorkflowName + " workflow end")
	return nil, nil
}
