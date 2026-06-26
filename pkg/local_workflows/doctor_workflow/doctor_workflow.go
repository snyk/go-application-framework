package doctor_workflow

import (
	"fmt"
	"io"
	"os"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/logsummary"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	doctorWorkflowName = "doctor"

	inputFlag       = "input"
	noLiveCheckFlag = "no-live-check"
)

var WORKFLOWID_DOCTOR workflow.Identifier = workflow.NewWorkflowIdentifier(doctorWorkflowName)

func InitDoctorWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(doctorWorkflowName, pflag.ExitOnError)
	flags.String(inputFlag, "", "Path to a Snyk CLI debug log file. If absent, reads debug logs from STDIN.")
	flags.Bool(noLiveCheckFlag, false, "Skip the live authentication and connectivity checks.")

	_, err := engine.Register(
		WORKFLOWID_DOCTOR,
		workflow.ConfigurationOptionsFromFlagset(flags),
		doctorEntryPoint,
	)
	return err
}

func doctorEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	return runDoctor(invocationCtx, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())))
}

func runDoctor(invocationCtx workflow.InvocationContext, stdin io.Reader, stdinIsTerminal bool) ([]workflow.Data, error) {
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	inputPath := config.GetString(inputFlag)
	if inputPath == "" && stdinIsTerminal {
		return nil, cli.NewCommandArgsError(
			fmt.Sprintf("No debug log was provided. Pipe one in with 'snyk <command> -d 2>&1 | snyk doctor', or pass a log file with --%s <path>.", inputFlag),
		)
	}

	debugLog, err := readDebugLog(stdin, inputPath)
	if err != nil {
		return nil, err
	}

	summary := logsummary.Summarize(debugLog)
	logger.Debug().Msgf("doctor: summarized debug log (%d notable events from %d bytes)", len(summary.Highlights), len(debugLog))

	report := summary.Format()
	if config.GetBool(noLiveCheckFlag) {
		logger.Debug().Msg("doctor: --no-live-check set, skipping live checks")
	} else {
		live := livecheck.Run(invocationCtx)
		logger.Debug().Msgf("doctor: gathered live context (auth ok=%t)", live.Auth.OK)
		report += live.Format()
	}

	outputData := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DOCTOR, doctorWorkflowName),
		"text/plain",
		[]byte(report),
		workflow.WithLogger(logger),
		workflow.WithConfiguration(config),
	)
	return []workflow.Data{outputData}, nil
}

func readDebugLog(stdin io.Reader, inputPath string) (string, error) {
	if inputPath != "" {
		content, err := os.ReadFile(inputPath)
		if err != nil {
			return "", cli.NewGeneralCLIFailureError(
				fmt.Sprintf("Could not read the debug log file at '%s'. Check that the path is correct and the file is readable.", inputPath),
				snyk_errors.WithCause(err),
			)
		}
		return string(content), nil
	}

	content, err := io.ReadAll(stdin)
	if err != nil {
		return "", cli.NewGeneralCLIFailureError(
			"Could not read the debug log from standard input.",
			snyk_errors.WithCause(err),
		)
	}
	return string(content), nil
}
