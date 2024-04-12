package code_workflow

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const summaryType = "sast"

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
	transactionName string
	operationName   string
}

func (c *codeClientSpan) SetTransactionName(name string) { c.transactionName = name }
func (c *codeClientSpan) StartSpan(ctx context.Context)  {}
func (c *codeClientSpan) Finish()                        {}
func (c *codeClientSpan) GetOperation() string           { return c.operationName }
func (c *codeClientSpan) GetTxName() string              { return c.transactionName }
func (c *codeClientSpan) GetTraceId() string             { return "" } // TODO: interaction id
func (c *codeClientSpan) Context() context.Context       { return context.Background() }
func (c *codeClientSpan) GetDurationMs() int64           { return 0 }

type codeClientInstrumentor struct{}

func (c *codeClientInstrumentor) StartSpan(ctx context.Context, operation string) observability.Span {
	return &codeClientSpan{operationName: operation}
}
func (c *codeClientInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) observability.Span {
	return &codeClientSpan{operationName: operation, transactionName: txName}
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

func EntryPointNative(invocationCtx workflow.InvocationContext) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	id := invocationCtx.GetWorkflowIdentifier()

	changedFiles := make(map[string]bool)
	path := config.GetString(configuration.INPUT_DIRECTORY)
	interactionId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Interaction ID: %s", interactionId)
	logger.Debug().Msgf("Path: %s", path)

	ctx := context.Background()
	codeInstrumentor := &codeClientInstrumentor{}
	codeErrorReporter := &codeClientErrorReporter{}
	httpClient := http.NewHTTPClient(invocationCtx.GetNetworkAccess().GetHttpClient, http.WithLogger(logger))
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

	sarifData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "sarif"), result.Sarif, "application/json")
	if err != nil {
		return nil, err
	}

	summary := createCodeSummary(result)
	summaryData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "summary"), summary, "application/json")
	if err != nil {
		return nil, err
	}

	return []workflow.Data{sarifData, summaryData}, nil
}

// Create new Workflow data out of the given object and content type
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

// Convert Sarif Level to internal Severity
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

// Iterate through the sarif data and create a summary out of it.
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

			// evaluate if the result is suppressed/ignored or not
			if len(result.Suppressions) > 0 {
				resultMap[severity].Ignored++
			} else {
				resultMap[severity].Open++
			}
		}
	}

	// fill final map
	for k, v := range resultMap {
		local := *v
		local.Severity = k
		summary.Results = append(summary.Results, local)
	}

	return summary
}
