package localworkflows

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/deepcode"
	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
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
	return strings.Replace(c.localConfiguration.GetString(configuration.API_URL), "api", "deeproxy", -1) // TODO: what URL
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
				logger.Debug().Msg(path)
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
		logger.Debug().Msg("Ignores: Consistent")

		ctx := context.Background()
		codeInstrumentor := &codeClientInstrumentor{}
		codeErrorReporter := &codeClientErrorReporter{}

		// invoke code-client-go
		httpClient := http.NewHTTPClient(logger, &codeClientConfig{
			localConfiguration: config,
		}, invocationCtx.GetNetworkAccess().GetHttpClient, codeInstrumentor, codeErrorReporter)

		snykCode := deepcode.NewSnykCodeClient(logger, httpClient, codeInstrumentor)

		bundleManager := bundle.NewBundleManager(logger, snykCode, codeInstrumentor, codeErrorReporter)
		codeScanner := codeclient.NewCodeScanner(bundleManager, codeInstrumentor, codeErrorReporter, logger)

		changedFiles := make(map[string]bool)
		path := config.GetString(configuration.INPUT_DIRECTORY)

		files := make(chan string)
		getFilesForPath(path, files, logger)

		sarif, _, err := codeScanner.UploadAndAnalyze(ctx, path, files, changedFiles)
		fmt.Println(sarif)

		return nil, err
	} else {
		logger.Debug().Msg("Ignores: legacy")

		// run legacycli
		result, err = engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	}

	return result, err
}
