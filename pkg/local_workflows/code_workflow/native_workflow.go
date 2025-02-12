package code_workflow

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

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
	RemoteRepoUrlFlagname     = "remote-repo-url"
	ConfigurationTestFLowName = "internal_code_test_flow_name"
)

type OptionalAnalysisFunctions func(string, func() *http.Client, *zerolog.Logger, configuration.Configuration, ui.UserInterface) (*sarif.SarifResponse, error)

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

	analyzeFnc := defaultAnalyzeFunction
	if len(opts) == 1 {
		analyzeFnc = opts[0]
	}

	result, err := analyzeFnc(path, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config, invocationCtx.GetUserInterface())

	if err != nil {
		return nil, err
	}

	if result == nil {
		result = &sarif.SarifResponse{}
	} else {
		sarifData, sarifError := createCodeWorkflowData(
			workflow.NewTypeIdentifier(id, "sarif"),
			config,
			&result.Sarif,
			content_type.SARIF_JSON,
			path,
			logger)
		if sarifError != nil {
			return nil, sarifError
		}

		output = append(output, sarifData)
	}

	summary := sarif2.CreateCodeSummary(&result.Sarif, config.GetString(configuration.INPUT_DIRECTORY))
	summaryData, err := createCodeWorkflowData(
		workflow.NewTypeIdentifier(id, "summary"),
		config,
		summary,
		content_type.TEST_SUMMARY,
		path,
		logger)
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
func defaultAnalyzeFunction(path string, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface) (*sarif.SarifResponse, error) {
	var result *sarif.SarifResponse
	interactionId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	target, files, err := determineAnalyzeInput(path, config, logger)
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Path: %s", path)
	logger.Debug().Msgf("Target: %s", target)
	logger.Debug().Msgf("Request ID: %s", interactionId)

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
		codeclient.WithFlow(config.GetString(ConfigurationTestFLowName)),
	)

	result, _, err = codeScanner.UploadAndAnalyze(ctx, interactionId, target, files, changedFiles)
	return result, err
}

func determineAnalyzeInput(path string, config configuration.Configuration, logger *zerolog.Logger) (scan.Target, <-chan string, error) {
	var files <-chan string

	pathIsDirectory := false
	if fileinfo, fileInfoErr := os.Stat(path); fileInfoErr == nil && fileinfo.IsDir() {
		pathIsDirectory = true
	}

	if !pathIsDirectory {
		target, err := scan.NewRepositoryTarget(filepath.Dir(path), scan.WithRepositoryUrl(config.GetString(RemoteRepoUrlFlagname)))
		if err != nil {
			logger.Warn().Err(err)
		}

		files = func() <-chan string {
			var f = make(chan string)
			go func() {
				f <- path
				close(f)
			}()
			return f
		}()
		return target, files, nil
	}

	target, err := scan.NewRepositoryTarget(path, scan.WithRepositoryUrl(config.GetString(RemoteRepoUrlFlagname)))
	if err != nil {
		logger.Warn().Err(err)
	}

	files, err = getFilesForPath(path, logger, config.GetInt(configuration.MAX_THREADS))
	if err != nil {
		return nil, nil, err
	}

	return target, files, nil
}

// Return a channel that notifies each file in the path that doesn't match the filter rules
func getFilesForPath(path string, logger *zerolog.Logger, max_threads int) (<-chan string, error) {
	filter := utils.NewFileFilter(path, logger, utils.WithThreadNumber(max_threads))
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, err
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}

// Create new Workflow data out of the given object and content type
func createCodeWorkflowData(id workflow.Identifier, config configuration.Configuration, obj any, contentType string, path string, logger *zerolog.Logger) (workflow.Data, error) {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	data := workflow.NewData(
		id,
		contentType,
		bytes,
		workflow.WithConfiguration(config),
		workflow.WithLogger(logger),
	)

	data.SetContentLocation(path)

	return data, nil
}
