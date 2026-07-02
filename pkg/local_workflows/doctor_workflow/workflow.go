package doctor_workflow

import (
	"bytes"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/livecheck"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func doctorEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	return runDoctor(invocationCtx, os.Stdin, term.IsTerminal(int(os.Stdin.Fd())))
}

func runDoctor(invocationCtx workflow.InvocationContext, stdin io.Reader, stdinIsTerminal bool) ([]workflow.Data, error) {
	ctx := invocationCtx.Context()
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()

	// 1. Open input
	reader, err := diagnosis.OpenInput(config.GetString(inputFlag), stdin, stdinIsTerminal)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// 2. Analyze
	report, err := diagnosis.Analyze(ctx, reader, diagnosis.DefaultLogChecks())
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("doctor: analyzed debug log (%d findings)", len(report.Findings))

	// 3. Live checks (auth now, connectivity later), unless disabled — they
	// append to the same findings stream.
	if config.GetBool(noLiveCheckFlag) {
		logger.Debug().Msg("doctor: --no-live-check set, skipping live checks")
	} else {
		live := livecheck.Run(invocationCtx)
		report.Findings = append(report.Findings, live...)
		logger.Debug().Msgf("doctor: gathered %d live-check finding(s)", len(live))
	}

	// 4. Format — select by --json flag
	var buf bytes.Buffer
	contentType := "text/plain"
	if config.GetBool(jsonFlag) {
		contentType = "application/json"
		err = diagnosis.FormatJSON(&buf, report)
	} else {
		err = diagnosis.FormatText(&buf, report)
	}
	if err != nil {
		return nil, err
	}

	// 5. Package
	data := workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_DOCTOR, doctorWorkflowName),
		contentType,
		buf.Bytes(),
		workflow.WithConfiguration(config),
		workflow.WithLogger(logger),
	)
	return []workflow.Data{data}, nil
}
