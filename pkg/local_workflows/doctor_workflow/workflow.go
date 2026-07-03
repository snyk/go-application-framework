package doctor_workflow

import (
	"bytes"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck/connectivity"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func doctorEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	return runDoctor(invocationCtx, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())))
}

func runDoctor(invocationCtx workflow.InvocationContext, stdin io.Reader, stdinIsTerminal bool) ([]workflow.Data, error) {
	ctx := invocationCtx.Context()
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	inputPath := config.GetString(inputFlag)
	// A log is available from --input or from a pipe (stdin is not a terminal).
	// A bare `snyk doctor` with neither has nothing to analyze, so it defaults to
	// live checks rather than erroring.
	isAnalyzeDebugLogs := inputPath != "" || !stdinIsTerminal
	hasLiveFlag := config.GetBool(liveFlag)
	shouldDoLiveChecks := hasLiveFlag || !isAnalyzeDebugLogs

	// Start connectivity in the background while log analysis and auth run.
	var connAsync *connectivity.AsyncCheck
	if shouldDoLiveChecks {
		connAsync = connectivity.StartAsync(invocationCtx)
	}

	// 1. Analyze the log when there is one; otherwise start from an empty report.
	report := &diagnosis.DoctorReport{SchemaVersion: diagnosis.SchemaVersion}
	if isAnalyzeDebugLogs {
		reader, err := diagnosis.OpenInput(inputPath, stdin, stdinIsTerminal)
		if err != nil {
			return nil, err
		}
		defer reader.Close()

		report, err = diagnosis.Analyze(ctx, reader, diagnosis.DefaultLogChecks())
		if err != nil {
			return nil, err
		}
		logger.Debug().Msgf("doctor: analyzed debug log (%d findings)", len(report.Findings))
	}

	// 2. Live checks touch the current environment. They run when requested via
	// --live, or by default for a bare invocation (no log to analyze).
	if shouldDoLiveChecks {
		live := livecheck.Run(invocationCtx, connAsync)
		report.Findings = append(report.Findings, live...)
		logger.Debug().Msgf("doctor: gathered %d live-check finding(s)", len(live))
	}

	// 3. Format — select by --json flag
	var buf bytes.Buffer
	contentType := "text/plain"
	render := diagnosis.FormatText
	if config.GetBool(jsonFlag) {
		contentType = "application/json"
		render = diagnosis.FormatJSON
	}
	if err := render(&buf, report); err != nil {
		return nil, err
	}

	// 4. Package
	data := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DOCTOR, doctorWorkflowName),
		contentType,
		buf.Bytes(),
		workflow.WithConfiguration(config),
		workflow.WithLogger(logger),
	)
	return []workflow.Data{data}, nil
}
