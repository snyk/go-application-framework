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
	"github.com/snyk/error-catalog-golang-public/code"

	sarif2 "github.com/snyk/go-application-framework/internal/utils/sarif"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	RemoteRepoUrlFlagname       = "remote-repo-url"
	ConfigurationCategoryFilter = "sarif-category-filter"
)

type OptionalAnalysisFunctions func(scan.Target, func() *http.Client, *zerolog.Logger, configuration.Configuration, ui.UserInterface) (*sarif.SarifResponse, error)

type ProgressTrackerFactory struct {
	userInterface ui.UserInterface
	logger        *zerolog.Logger
}

func (p ProgressTrackerFactory) GenerateTracker() scan.Tracker {
	return &ProgressTrackerAdapter{
		bar:    p.userInterface.NewProgressBar(),
		logger: p.logger,
	}
}

type ProgressTrackerAdapter struct {
	bar    ui.ProgressBar
	logger *zerolog.Logger
}

func (p ProgressTrackerAdapter) Begin(title, message string) {
	if len(message) > 0 {
		p.bar.SetTitle(title + " - " + message)
	} else {
		p.bar.SetTitle(title)
	}

	err := p.bar.UpdateProgress(ui.InfiniteProgress)
	if err != nil {
		p.logger.Err(err).Msg("Failed to update progress")
	}
}

func (p ProgressTrackerAdapter) End(message string) {
	p.bar.SetTitle(message)
	err := p.bar.Clear()
	if err != nil {
		p.logger.Err(err).Msg("Failed to clear progress")
	}
}

func EntryPointNative(invocationCtx workflow.InvocationContext, opts ...OptionalAnalysisFunctions) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	id := invocationCtx.GetWorkflowIdentifier()

	output := []workflow.Data{}
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

	result, err := analyzeFnc(target, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config, invocationCtx.GetUserInterface())

	if err != nil {
		return nil, err
	}

	if result == nil {
		result = &sarif.SarifResponse{}
	} else {
		categoryFilter := config.GetStringSlice(ConfigurationCategoryFilter)
		filterSarifResultsByCategory(result, categoryFilter)

		sarifData, sarifError := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "sarif"), &result.Sarif, content_type.SARIF_JSON, path)
		if sarifError != nil {
			return nil, sarifError
		}

		output = append(output, sarifData)
	}

	summary := sarif2.CreateCodeSummary(&result.Sarif)
	summaryData, err := createCodeWorkflowData(workflow.NewTypeIdentifier(id, "summary"), summary, content_type.TEST_SUMMARY, path)
	if err != nil {
		return nil, err
	}

	// Check for empty summary
	if summary.Artifacts == 0 {
		summaryData.AddError(code.NewUnsupportedProjectError("Snyk was unable to find supported files."))
	}
	output = append(output, summaryData)

	return output, nil
}

// default function that uses the code-client-go library
func defaultAnalyzeFunction(target scan.Target, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface) (*sarif.SarifResponse, error) {
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

	progressFactory := ProgressTrackerFactory{
		userInterface: userInterface,
		logger:        logger,
	}

	codeScanner := codeclient.NewCodeScanner(
		codeScannerConfig,
		httpClient,
		codeclient.WithLogger(logger),
		codeclient.WithTrackerFactory(progressFactory),
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
