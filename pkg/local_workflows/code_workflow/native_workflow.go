package code_workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils"
	sarif2 "github.com/snyk/go-application-framework/pkg/utils/sarif"
	"github.com/snyk/go-application-framework/pkg/utils/git"
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

// codeAnalysisDependencies holds functions that can be injected for testing or alternative implementations.
type codeAnalysisDependencies struct {
	determineAnalyzeInputFunc func(path string, config configuration.Configuration, logger *zerolog.Logger) (scan.Target, <-chan string, error)
	getReportModeFunc         func(config configuration.Configuration) (reportType, error)
}

type AnalysisResult struct {
	SarifResponse  *sarif.SarifResponse
	ResultMetaData *scan.ResultMetaData
	GitContext     *local_models.GitContext
}

type OptionalAnalysisFunctions func(string, func() *http.Client, *zerolog.Logger, configuration.Configuration, ui.UserInterface, codeAnalysisDependencies) (*AnalysisResult, error)

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

	deps := codeAnalysisDependencies{
		determineAnalyzeInputFunc: determineAnalyzeInput,
		getReportModeFunc:         GetReportMode,
	}

	result, err := analyzeFnc(path, invocationCtx.GetNetworkAccess().GetHttpClient, logger, config, invocationCtx.GetUserInterface(), deps)
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Result metadata: %+v", result.ResultMetaData)

	resultAvailable := true
	if result == nil || result.SarifResponse == nil {
		resultAvailable = false
		if result == nil {
			result = &AnalysisResult{
				SarifResponse: &sarif.SarifResponse{},
			}
		} else {
			result.SarifResponse = &sarif.SarifResponse{}
		}
	}

	summary := sarif2.CreateCodeSummary(&result.SarifResponse.Sarif, config.GetString(configuration.INPUT_DIRECTORY))
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
		localFindings, lfError := local_models.TransformToLocalFindingModelFromSarifWithGitContext(&result.SarifResponse.Sarif, summary, result.GitContext)
		if lfError != nil {
			return nil, lfError
		}

		// if available add a report link to the findings
		if result.ResultMetaData != nil && len(result.ResultMetaData.WebUiUrl) > 0 {
			localFindings.Links[local_models.LINKS_KEY_REPORT] = fmt.Sprintf("%s%s", config.GetString(configuration.WEB_APP_URL), result.ResultMetaData.WebUiUrl)
		}

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
func defaultAnalyzeFunction(path string, httpClientFunc func() *http.Client, logger *zerolog.Logger, config configuration.Configuration, userInterface ui.UserInterface, deps codeAnalysisDependencies) (*AnalysisResult, error) {
	var result *AnalysisResult
	var err error

	requestId, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	reportMode, err := deps.getReportModeFunc(config)
	if err != nil {
		return nil, err
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
			return nil, errors.Join(errors.New("\"project-id\" must be a valid UUID"), parseErr)
		}

		option := codeclient.ReportRemoteTest(projectId, config.GetString(ConfigurationCommitId))
		sarifResponse, resultMetaData, err := codeScanner.AnalyzeRemote(ctx, option)
		if err != nil {
			return nil, err
		}
		result = &AnalysisResult{
			SarifResponse:  sarifResponse,
			ResultMetaData: resultMetaData,
		}
		return result, err
	}

	// use case: stateful local code testing
	if reportMode == localCode {
		option := codeclient.ReportLocalTest(config.GetString(ConfigurationProjectName), config.GetString(ConfigurationTargetName), config.GetString(ConfigurationTargetReference))
		analysisOptions = append(analysisOptions, option)
	}

	target, files, err := deps.determineAnalyzeInputFunc(path, config, logger)
	if err != nil {
		return nil, err
	}

	logger.Debug().Msgf("Path: %s", path)
	logger.Debug().Msgf("Target: %s", target)

	changedFiles := make(map[string]bool)

	sarifResponse, _, resultMetaData, err := codeScanner.UploadAndAnalyzeWithOptions(ctx, requestId, target, files, changedFiles, analysisOptions...)
	if err != nil {
		return nil, err
	}
	
	// Create git context from target information
	var gitContext *local_models.GitContext
	if target != nil {
		if repoTarget, ok := target.(*scan.RepositoryTarget); ok {
			logger.Debug().Msgf("Extracting git context from repository target: %s", repoTarget.GetPath())
			
			branch, err := git.BranchNameFromDir(repoTarget.GetPath())
			if err != nil {
				logger.Debug().Err(err).Msg("Failed to get current branch")
			} else {
				logger.Debug().Msgf("Current branch: %s", branch)
			}

			commitHash, err := git.CommitHashFromDir(repoTarget.GetPath())
			if err != nil {
				logger.Debug().Err(err).Msg("Failed to get current commit hash")
			} else {
				logger.Debug().Msgf("Current commit hash: %s", commitHash)
			}

			gitContext = &local_models.GitContext{
				RepositoryUrl: repoTarget.GetRepositoryUrl(),
				Branch:        branch,
				CommitHash:    commitHash,
			}
			logger.Debug().Msgf("Created git context: %+v", gitContext)
		} else {
			logger.Debug().Msgf("Target is not a RepositoryTarget, type: %T", target)
		}
	} else {
		logger.Debug().Msg("Target is nil, cannot determine git context - repository context tip will be shown")
	}

	result = &AnalysisResult{
		SarifResponse:  sarifResponse,
		ResultMetaData: resultMetaData,
		GitContext:     gitContext,
	}
	return result, err
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
