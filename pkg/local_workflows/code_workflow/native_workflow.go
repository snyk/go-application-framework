package code_workflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"

	gUuid "github.com/google/uuid"
	"github.com/hashicorp/go-uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/error-catalog-golang-public/code"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils"
	sarif2 "github.com/snyk/go-application-framework/pkg/utils/sarif"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ConfigurationTestFLowName    = "internal_code_test_flow_name"
	ConfigurationReportFlag      = "report"
	ConfigurationProjectName     = "project-name"
	ConfigurationTargetName      = "target-name"
	ConfigurationTargetReference = "target-reference"
	ConfigurationProjectId       = "project-id"
	ConfigurationCommitId        = "commit-id"
	ConfigurationSastEnabled     = "internal_sast_enabled"
	ConfigurationSastSettings    = "internal_sast_settings"
	ConfigurarionSlceEnabled     = "internal_snyk_scle_enabled"
	FfNameNativeImplementation   = "snykCodeClientNativeImplementation"
)

type reportType string

const (
	localCode  reportType = "local_code"
	remoteCode reportType = "remote_code"
	noReport   reportType = "no_report"
)

type OptionalAnalysisFunctions func(string, func() *http.Client, *zerolog.Logger, configuration.Configuration, ui.UserInterface) (*sarif.SarifResponse, *scan.ResultMetaData, error)

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

func trackUsage(network networking.NetworkAccess, config configuration.Configuration) {
	apiUrl := config.GetUrl(configuration.API_URL)
	apiUrl.Path = path.Join(apiUrl.Path, "v1/track-sast-usage/cli")
	apiUrl.RawQuery = "org=" + config.GetString(configuration.ORGANIZATION)
	apiUrlString := apiUrl.String()

	resp, err := network.GetHttpClient().Post(apiUrlString, "application/json", nil)
	if err != nil {
		return
	}

	resp.Body.Close()
}

func EntryPointNative(invocationCtx workflow.InvocationContext, opts ...OptionalAnalysisFunctions) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	id := invocationCtx.GetWorkflowIdentifier()

	// track usage based on
	trackUsage(invocationCtx.GetNetworkAccess(), config)

	output := []workflow.Data{}
	path := config.GetString(configuration.INPUT_DIRECTORY)

	analyzeFnc := defaultAnalyzeFunction
	if len(opts) == 1 {
		analyzeFnc = opts[0]
	}

	result, resultMetaData, err := analyzeFnc(path, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config, invocationCtx.GetUserInterface())
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Result metadata: %+v", resultMetaData)

	resultAvailable := true
	if result == nil {
		resultAvailable = false
		result = &sarif.SarifResponse{}
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

	if resultAvailable {
		// transform sarif to findings
		localFindings, lfError := local_models.TransformToLocalFindingModelFromSarif(&result.Sarif, summary)
		if lfError != nil {
			return nil, lfError
		}

		// translate metadata to findings
		local_models.TranslateMetadataToLocalFindingModel(resultMetaData, &localFindings, config)

		targetId, targetIdError := instrumentation.GetTargetId(config.GetString(configuration.INPUT_DIRECTORY), instrumentation.AutoDetectedTargetId, instrumentation.WithConfiguredRepository(config))
		if targetIdError != nil {
			logger.Printf("Failed to derive target id, %v", targetIdError)
		}
		localFindings.Links["targetid"] = targetId

		findingsData, findingsError := createCodeWorkflowData(
			workflow.NewTypeIdentifier(id, "findings"),
			config,
			localFindings,
			content_type.LOCAL_FINDING_MODEL,
			path,
			logger)
		if findingsError != nil {
			return nil, findingsError
		}
		output = append(output, findingsData)
	}

	return output, err
}

// default function that uses the code-client-go library
func defaultAnalyzeFunction(path string, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	var result *sarif.SarifResponse
	var resultMetaData *scan.ResultMetaData
	requestId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, nil, err
	}

	reportMode, err := GetReportMode(config)
	if err != nil {
		return nil, nil, err
	}

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

	analysisOptions := []codeclient.AnalysisOption{}

	codeScannerOptions := []codeclient.OptionFunc{
		codeclient.WithLogger(logger),
		codeclient.WithTrackerFactory(progressFactory),
		codeclient.WithFlow(config.GetString(ConfigurationTestFLowName)),
	}

	codeScanner := codeclient.NewCodeScanner(
		codeScannerConfig,
		httpClient,
		codeScannerOptions...,
	)

	logger.Debug().Msgf("Request ID: %s", requestId)
	logger.Debug().Msgf("Report Mode: %s", reportMode)

	// use case: stateful remote code testing
	if reportMode == remoteCode {
		projectId, parseErr := gUuid.Parse(config.GetString(ConfigurationProjectId))
		if parseErr != nil {
			return nil, nil, errors.Join(errors.New("\"project-id\" must be a valid UUID"), parseErr)
		}

		option := codeclient.ReportRemoteTest(projectId, config.GetString(ConfigurationCommitId))
		result, resultMetaData, err = codeScanner.AnalyzeRemote(ctx, option)
		return result, resultMetaData, err
	}

	// use case: stateful local code testing
	if reportMode == localCode {
		option := codeclient.ReportLocalTest(config.GetString(ConfigurationProjectName), config.GetString(ConfigurationTargetName), config.GetString(ConfigurationTargetReference))
		analysisOptions = append(analysisOptions, option)
	}

	target, files, err := determineAnalyzeInput(path, config, logger)
	if err != nil {
		return nil, nil, err
	}

	logger.Debug().Msgf("Path: %s", path)
	logger.Debug().Msgf("Target: %s", target)

	changedFiles := make(map[string]bool)

	result, _, resultMetaData, err = codeScanner.UploadAndAnalyzeWithOptions(ctx, requestId, target, files, changedFiles, analysisOptions...)
	return result, resultMetaData, err
}

func determineAnalyzeInput(path string, config configuration.Configuration, logger *zerolog.Logger) (scan.Target, <-chan string, error) {
	var files <-chan string

	pathIsDirectory := false
	if fileinfo, fileInfoErr := os.Stat(path); fileInfoErr == nil && fileinfo.IsDir() {
		pathIsDirectory = true
	}

	if !pathIsDirectory {
		target, err := scan.NewRepositoryTarget(filepath.Dir(path), scan.WithRepositoryUrl(config.GetString(configuration.FLAG_REMOTE_REPO_URL)))
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

	target, err := scan.NewRepositoryTarget(path, scan.WithRepositoryUrl(config.GetString(configuration.FLAG_REMOTE_REPO_URL)))
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
