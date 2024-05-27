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
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	sarif2 "github.com/snyk/go-application-framework/internal/utils/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	RemoteRepoUrlFlagname = "remote-repo-url"
)

type OptionalAnalysisFunctions func(scan.Target, func() *http.Client, *zerolog.Logger, configuration.Configuration) (*sarif.SarifResponse, error)

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

	target, err := scan.NewRepositoryTarget(path, scan.WithRepositoryUrl(config.GetString(RemoteRepoUrlFlagname)))
	if err != nil {
		logger.Warn().Err(err)
	}

	result, err := analyzeFnc(target, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config)
	if err != nil || result == nil {
		return nil, err
	}

	sarifData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "sarif"), &result.Sarif, content_type.SARIF_JSON, path)
	if err != nil {
		return nil, err
	}

	summary := sarif2.CreateCodeSummary(&result.Sarif, sarif2.WithCoverage(result.Coverage))
	summaryData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "summary"), summary, content_type.TEST_SUMMARY, path)
	if err != nil {
		return nil, err
	}

	// Check summary
	if summary.Artifacts == 0 {
		summaryData.AddError(snyk_errors.Error{
			ID:             "",
			Type:           "",
			Title:          "",
			StatusCode:     0,
			ErrorCode:      "",
			Level:          "",
			Links:          nil,
			Detail:         "",
			Meta:           nil,
			Cause:          nil,
			Classification: "",
			Logs:           nil,
		})
	}

	return []workflow.Data{sarifData, summaryData}, nil
}

// default function that uses the code-client-go library
func defaultAnalyzeFunction(target scan.Target, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration) (*sarif.SarifResponse, error) {
	var result *sarif.SarifResponse

	interactionId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Interaction ID: %s", interactionId)

	files, err := getFilesForPath(target.GetPath(), logger)
	if err != nil {
		return nil, err
	}

	changedFiles := make(map[string]bool)
	ctx := context.Background()
	httpClient := codeclienthttp.NewHTTPClient(
		httpClientFunc,
		codeclienthttp.WithLogger(logger),
	)
	codeScannerConfig := &codeClientConfig{
		localConfiguration: config,
	}
	codeScanner := codeclient.NewCodeScanner(
		codeScannerConfig,
		httpClient,
		codeclient.WithLogger(logger),
	)

	result, _, err = codeScanner.UploadAndAnalyze(ctx, interactionId, target, files, changedFiles)
	return result, err
}

// Return a channel that notifies each file in the path that doesn't match the filter rules
func getFilesForPath(path string, logger *zerolog.Logger) (<-chan string, error) {
	filter := utils.NewFileFilter(path, logger)
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
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
