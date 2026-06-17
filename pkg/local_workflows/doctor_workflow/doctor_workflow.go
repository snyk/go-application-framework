package doctor_workflow

import (
	"fmt"
	"io"
	"os"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	doctorWorkflowName = "doctor"

	inputFlag         = "input"
	includeReportFlag = "include-report"
	noLiveCheckFlag   = "no-live-check"
)

var WORKFLOWID_DOCTOR workflow.Identifier = workflow.NewWorkflowIdentifier(doctorWorkflowName)

func InitDoctorWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(doctorWorkflowName, pflag.ExitOnError)
	flags.String(inputFlag, "", "Path to a Snyk CLI debug log file. If absent, reads debug logs from STDIN.")
	flags.Bool(includeReportFlag, false, "Print the full consolidated report alongside the diagnosis.")
	flags.Bool(noLiveCheckFlag, false, "Skip the live authentication and connectivity checks.")

	_, err := engine.Register(
		WORKFLOWID_DOCTOR,
		workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(flags)),
		doctorEntryPoint,
	)
	return err
}

func doctorEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	debugLog, err := readDebugLog(config.GetString(inputFlag))
	if err != nil {
		return nil, err
	}

	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DOCTOR, doctorWorkflowName),
		"text/plain",
		[]byte(debugLog),
		workflow.WithLogger(logger),
		workflow.WithConfiguration(config),
	)
	return []workflow.Data{outputData}, nil
}

func readDebugLog(inputPath string) (string, error) {
	if inputPath != "" {
		content, err := os.ReadFile(inputPath)
		if err != nil {
			return "", cli.NewGeneralCLIFailureError(
				fmt.Sprintf("failed to read debug log from %s", inputPath),
				snyk_errors.WithCause(err),
			)
		}
		return string(content), nil
	}

	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
		return "", cli.NewCommandArgsError(
			fmt.Sprintf("no debug log provided: pipe one in (snyk test -d 2>&1 | snyk doctor) or use --%s <file>", inputFlag),
		)
	}
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", cli.NewGeneralCLIFailureError(
			"failed to read debug log from STDIN",
			snyk_errors.WithCause(err),
		)
	}
	return string(content), nil
}
