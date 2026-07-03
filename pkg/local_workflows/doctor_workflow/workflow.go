package doctor_workflow

import (
	"bytes"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck"
	"github.com/snyk/go-application-framework/pkg/ui/uitypes"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func doctorEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	return runDoctor(invocationCtx, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())))
}

func runDoctor(invocationCtx workflow.InvocationContext, stdin io.Reader, stdinIsTerminal bool) ([]workflow.Data, error) {
	ctx := invocationCtx.Context()
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	userInterface := invocationCtx.GetUserInterface()

	progressbar := userInterface.NewProgressBar()
	progressbar.SetTitle("Examining ...")
	progressbar.UpdateProgress(uitypes.InfiniteProgress)
	defer progressbar.Clear()

	inputPath := config.GetString(inputFlag)
	// A log is available from --input or from a pipe (stdin is not a terminal).
	// A bare `snyk doctor` with neither has nothing to analyze, so it defaults to
	// live checks rather than erroring.
	isAnalyzeDebugLogs := inputPath != "" || !stdinIsTerminal
	hasLiveFlag := config.GetBool(liveFlag)
	shouldDoLiveChecks := hasLiveFlag || !isAnalyzeDebugLogs

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
	} else {
		report.Summary.Fields = []diagnosis.KeyValue{
			{"Version", invocationCtx.GetRuntimeInfo().GetVersion()},
			{"API", config.GetString(configuration.API_URL)},
			{"Cache", config.GetString(configuration.CACHE_PATH)},
			{"Organization", config.GetString(configuration.ORGANIZATION)},
		}
	}

	// 2. Live checks touch the current environment. They run when requested via
	// --live, or by default for a bare invocation (no log to analyze).
	if shouldDoLiveChecks {
		live := livecheck.Run(invocationCtx)
		report.Findings = append(report.Findings, live...)
		logger.Debug().Msgf("doctor: gathered %d live-check finding(s)", len(live))
	}

	// 3. Format — select by --json flag
	var buf bytes.Buffer
	contentType := "text/plain"
	render := diagnosis.FormatTemplate
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
