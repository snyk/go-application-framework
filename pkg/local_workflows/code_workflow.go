package localworkflows

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	summaryType                  = "sast"
	codeWorkflowName             = "code.test"
	codeWorkflowExperimentalFlag = configuration.FLAG_EXPERIMENTAL
)

func GetCodeFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(codeWorkflowName, pflag.ExitOnError)

	// add flags here
	flagSet.Bool("sarif", false, "Output in sarif format")
	flagSet.Bool("json", false, "Output in json format")
	flagSet.Bool("report", false, "Share results with the Snyk Web UI")
	flagSet.String("severity-threshold", "", "Minimum severity level to report (low|medium|high)")
	flagSet.String("sarif-file-output", "", "Save test output in SARIF format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --sarif option.")
	flagSet.String("json-file-output", "", "Save test output in JSON format directly to the <OUTPUT_FILE_PATH> file, regardless of whether or not you use the --json option.")
	flagSet.String("project-name", "", "The name of the project to test.")
	flagSet.String("project-id", "", "The unique identifier of the project to test.")
	flagSet.String("commit-id", "", "The unique identifier of the commit to test.")
	flagSet.String("target-name", "", "The name of the target to test.")
	flagSet.String("target-file", "", "The path to the target file to test.")
	flagSet.String("remote-repo-url", "", "The URL of the remote repository to test.")
	flagSet.Bool("experimental", false, "Enable experimental code test command")

	return flagSet
}

// WORKFLOWID_CODE defines a new workflow identifier
var WORKFLOWID_CODE workflow.Identifier = workflow.NewWorkflowIdentifier(codeWorkflowName)

type codeClientConfig struct {
	localConfiguration configuration.Configuration
}

func (c *codeClientConfig) Organization() string {
	return c.localConfiguration.GetString(configuration.ORGANIZATION)
}

func (c *codeClientConfig) IsFedramp() bool {
	return c.localConfiguration.GetBool(configuration.IS_FEDRAMP)
}

func (c *codeClientConfig) SnykCodeApi() string {
	return strings.Replace(c.localConfiguration.GetString(configuration.API_URL), "api", "deeproxy", -1)
}

func (c *codeClientConfig) SnykApi() string {
	return c.localConfiguration.GetString(configuration.API_URL)
}

type codeClientErrorReporter struct{}

func (c *codeClientErrorReporter) FlushErrorReporting() {}
func (c *codeClientErrorReporter) CaptureError(err error, options observability.ErrorReporterOptions) bool {
	return true
}

type codeClientSpan struct {
	ctx             context.Context
	transactionName string
	operationName   string
}

func (c *codeClientSpan) SetTransactionName(name string) { c.transactionName = name }
func (c *codeClientSpan) StartSpan(ctx context.Context)  { c.ctx = ctx }
func (c *codeClientSpan) Finish()                        {}
func (c *codeClientSpan) GetOperation() string           { return c.operationName }
func (c *codeClientSpan) GetTxName() string              { return c.transactionName }
func (c *codeClientSpan) GetTraceId() string             { return "" } // TODO: interaction id
func (c *codeClientSpan) Context() context.Context       { return c.ctx }
func (c *codeClientSpan) GetDurationMs() int64           { return 0 }

type codeClientInstrumentor struct{}

func (c *codeClientInstrumentor) StartSpan(ctx context.Context, operation string) observability.Span {
	return &codeClientSpan{ctx: ctx, operationName: operation}
}
func (c *codeClientInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) observability.Span {
	return &codeClientSpan{ctx: ctx, operationName: operation, transactionName: txName}
}
func (c *codeClientInstrumentor) Finish(span observability.Span) {
	span.Finish()
}

// todo: recursively iterate and filter
func getFilesForPath(path string, results chan<- string, logger *zerolog.Logger) {
	go func() {
		defer close(results)
		err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() && err == nil {
				//logger.Debug().Msg(path)
				results <- path
			}
			return err
		})

		if err != nil {
			logger.Error().Err(err)
		}
	}()
}

// InitCodeWorkflow initializes the code workflow before registering it with the engine.
func InitCodeWorkflow(engine workflow.Engine) error {
	// register workflow with engine
	flags := GetCodeFlagSet()
	_, err := engine.Register(WORKFLOWID_CODE, workflow.ConfigurationOptionsFromFlagset(flags), codeWorkflowEntryPoint)
	return err
}

// codeWorkflowEntryPoint is the entry point for the code workflow.
// it provides a wrapper for the legacycli workflow
func codeWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	engine := invocationCtx.GetEngine()

	useExperimentalOutput := config.GetBool(codeWorkflowExperimentalFlag) && !slices.Contains(os.Args, "--report")

	if useExperimentalOutput {
		args := []string{"--json"}

		// Add the rest of the arguments
		for _, arg := range os.Args[1:] {
			if arg == "--experimental" || arg == "--json" || arg == "--sarif" {
				continue
			}

			args = append(args, arg)
		}

		config.Set(configuration.RAW_CMD_ARGS, args)
	} else {
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
	}

	config.Set(configuration.WORKFLOW_USE_STDIO, true)

	logger.Debug().Msg("code workflow start")

	if config.GetBool(configuration.FF_CODE_CONSISTENT_IGNORES) {
		changedFiles := make(map[string]bool)
		path := config.GetString(configuration.INPUT_DIRECTORY)
		interactionId, err := uuid.GenerateUUID()
		if err != nil {
			return nil, err
		}

		logger.Debug().Msg("Ignores: Consistent")
		logger.Debug().Msgf("Interaction ID: %s", interactionId)
		logger.Debug().Msgf("Path: %s", path)

		ctx := context.Background()
		codeInstrumentor := &codeClientInstrumentor{}
		codeErrorReporter := &codeClientErrorReporter{}
		httpClient := http.NewHTTPClient(logger, invocationCtx.GetNetworkAccess().GetHttpClient, codeInstrumentor, codeErrorReporter)
		codeScannerConfig := &codeClientConfig{
			localConfiguration: config,
		}
		codeScanner := codeclient.NewCodeScanner(httpClient, codeScannerConfig, codeInstrumentor, codeErrorReporter, logger)

		files := make(chan string)
		getFilesForPath(path, files, logger)

		result, _, err := codeScanner.UploadAndAnalyze(ctx, interactionId, path, files, changedFiles)
		if err != nil || result == nil {
			return nil, err
		}

		sarifData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(WORKFLOWID_CODE, "sarif"), result.Sarif, "application/json")
		if err != nil {
			return nil, err
		}

		summary := createCodeSummary(result)
		summaryData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(WORKFLOWID_CODE, "summary"), summary, "application/json")
		if err != nil {
			return nil, err
		}

		return []workflow.Data{sarifData, summaryData}, nil

	} else {
		logger.Debug().Msg("Ignores: legacy")

		// run legacycli
		result, err = engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	}

	return result, err
}

func createCodeWorkflowData(id workflow.Identifier, obj any, contentType string) (workflow.Data, error) {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	data := workflow.NewData(
		id,
		contentType,
		bytes,
	)

	return data, nil
}

func sarifLevelToSeverity(level string) string {
	var severity string
	if level == "note" {
		severity = "Low"
	} else if level == "warning" {
		severity = "Medium"
	} else if level == "error" {
		severity = "High"
	} else {
		severity = "unmapped"
	}

	return severity
}

func createCodeSummary(input *sarif.SarifResponse) *json_schemas.TestSummary {
	if input == nil {
		return nil
	}

	summary := &json_schemas.TestSummary{
		Type: summaryType,
	}
	resultMap := map[string]*json_schemas.TestSummaryResult{}

	for _, run := range input.Sarif.Runs {
		for _, result := range run.Results {
			severity := sarifLevelToSeverity(result.Level)

			if _, ok := resultMap[severity]; !ok {
				resultMap[severity] = &json_schemas.TestSummaryResult{}
			}

			resultMap[severity].Total++
		}
	}

	for k, v := range resultMap {
		local := *v
		local.Severity = k
		summary.Results = append(summary.Results, local)
	}

	return summary
}
