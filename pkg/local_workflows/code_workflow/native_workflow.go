package code_workflow

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hashicorp/go-uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/sarif"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	summaryType        = "sast"
	SARIF_CONTENT_TYPE = "application/sarif+json"
)

type OptionalAnalysisFunctions func(string, func() *http.Client, *zerolog.Logger, configuration.Configuration) (*sarif.SarifResponse, error)

func EntryPointNative(invocationCtx workflow.InvocationContext, opts ...OptionalAnalysisFunctions) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	id := invocationCtx.GetWorkflowIdentifier()

	path := config.GetString(configuration.INPUT_DIRECTORY)

	logger.Debug().Msgf("Path: %s", path)

	analyzeFnc := defaultAnalyzeFunction
	if len(opts) == 1 {
		analyzeFnc = opts[0]
	}

	result, err := analyzeFnc(path, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config)
	if err != nil || result == nil {
		return nil, err
	}

	sarifData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "sarif"), &result.Sarif, SARIF_CONTENT_TYPE, path)
	if err != nil {
		return nil, err
	}

	summary := createCodeSummary(&result.Sarif)
	summaryData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "summary"), summary, content_type.TEST_SUMMARY, path)
	if err != nil {
		return nil, err
	}

	return []workflow.Data{sarifData, summaryData}, nil
}

// default function that uses the code-client-go library
func defaultAnalyzeFunction(path string, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration) (*sarif.SarifResponse, error) {
	var result *sarif.SarifResponse

	interactionId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Interaction ID: %s", interactionId)

	files, err := getFilesForPath(path)
	if err != nil {
		return nil, err
	}

	changedFiles := make(map[string]bool)
	ctx := context.Background()
	codeInstrumentor := &codeClientInstrumentor{}
	codeErrorReporter := &codeClientErrorReporter{}
	httpClient := codeclienthttp.NewHTTPClient(httpClientFunc, codeclienthttp.WithLogger(logger))
	codeScannerConfig := &codeClientConfig{
		localConfiguration: config,
	}
	codeScanner := codeclient.NewCodeScanner(httpClient, codeScannerConfig, codeInstrumentor, codeErrorReporter, logger)
	result, _, err = codeScanner.UploadAndAnalyze(ctx, interactionId, path, files, changedFiles)
	return result, err
}

// Return a channel that notifies each file in the path that doesn't match the filter rules
func getFilesForPath(path string) (<-chan string, error) {
	filter := utils.NewFileFilter(path)
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore"})
	if err != nil {
		return nil, err
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}

// Create new Workflow data out of the given object and content type
func createCodeWorkflowData(id workflow.Identifier, obj any, contentType string, path string) (workflow.Data, error) {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	data := workflow.NewData(
		id,
		contentType,
		bytes,
	)

	data.SetContentLocation(path)

	return data, nil
}

// Convert Sarif Level to internal Severity
func sarifLevelToSeverity(level string) string {
	var severity string
	if level == "note" {
		severity = "low"
	} else if level == "warning" {
		severity = "medium"
	} else if level == "error" {
		severity = "high"
	} else {
		severity = "unmapped"
	}

	return severity
}

// Iterate through the sarif data and create a summary out of it.
func createCodeSummary(input *sarif.SarifDocument) *json_schemas.TestSummary {
	if input == nil {
		return nil
	}

	summary := json_schemas.NewTestSummary(summaryType)
	resultMap := map[string]*json_schemas.TestSummaryResult{}

	for _, run := range input.Runs {
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
