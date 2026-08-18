package output_workflow

import (
	"errors"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func getTotalNumberOfUnifiedFindings(results []testapi.TestResult) int {
	if results == nil {
		return 0
	}

	var count int
	for _, result := range results {
		summary := result.GetEffectiveSummary()
		if summary != nil {
			count += int(summary.Count)
		}
	}
	return count
}

func useRendererWithUnifiedModel(name string, wEntry *WriterEntry, results []testapi.TestResult, assetLink string, invocation workflow.InvocationContext) error {
	debugLogger := invocation.GetEnhancedLogger()

	if !wEntry.renderEmptyData && getTotalNumberOfUnifiedFindings(results) == 0 {
		debugLogger.Info().Msgf("UFM - [%s] The input is empty, skipping rendering!", name)
		return nil
	}

	debugLogger.Info().Msgf("UFM - [%s] Creating UFM renderer", name)

	defer func() {
		closeErr := wEntry.writer.Close()
		if closeErr != nil {
			debugLogger.Err(closeErr).Msgf("UFM - [%s] Error while closing writer.", name)
		}
	}()

	config := invocation.GetConfiguration()
	renderer := presenters.NewUfmRenderer(
		results,
		config,
		wEntry.writer,
		presenters.UfmWithRuntimeInfo(invocation.GetRuntimeInfo()),
		presenters.UfmWithAssetLink(assetLink),
	)

	debugLogger.Info().Msgf("UFM - [%s] Rendering %s with %s", name, wEntry.mimeType, wEntry.templates)
	err := renderer.RenderTemplate(wEntry.templates, wEntry.mimeType)
	if err != nil {
		debugLogger.Warn().Err(err).Msgf("UFM - [%s] Failed to render local finding", name)
		return err
	}

	debugLogger.Info().Msgf("UFM - [%s] Rendering done", name)
	return nil
}

func getTestsFromWorkflowData(input []workflow.Data) ([]ufm.Test, []workflow.Data) {
	var tests []ufm.Test
	remainingData := []workflow.Data{}

	for _, data := range input {
		test := ufm.GetTestFromWorkflowData(data)
		if test != nil {
			tests = append(tests, *test)
			continue
		}
		remainingData = append(remainingData, data)
	}

	return tests, remainingData
}

// testResultsOf flattens the results of the given tests, for the rendering and counting that
// works a result at a time.
func testResultsOf(tests []ufm.Test) []testapi.TestResult {
	var results []testapi.TestResult
	for _, test := range tests {
		results = append(results, test.Results...)
	}
	return results
}

// assetLinkOf returns the inventory link of the asset covered by the given tests.
//
// A test has at most one asset, and only a test of an SBOM reports one at all, so there is
// never more than one link to show.
func assetLinkOf(tests []ufm.Test) string {
	for _, test := range tests {
		if link := test.AssetLink(); link != "" {
			return link
		}
	}
	return ""
}

// HandleContentTypeUnifiedModel handles the unified model content type.
func HandleContentTypeUnifiedModel(input []workflow.Data, invocation workflow.InvocationContext, writers WriterMap) ([]workflow.Data, error) {
	var err error
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	// Extract TestResults from workflow data
	tests, remainingData := getTestsFromWorkflowData(input)
	results := testResultsOf(tests)
	assetLink := assetLinkOf(tests)
	if len(results) == 0 {
		debugLogger.Info().Msg("UFM - No data to process")
		return remainingData, nil
	}

	threadCount := max(int64(config.GetInt(configuration.MAX_THREADS)), 1)
	debugLogger.Info().Msgf("UFM - Thread count: %d", threadCount)
	debugLogger.Info().Msgf("UFM - TestResults: %d", len(results))

	supportedMimeTypes := []MimeType2Template{
		{
			mimetype:  SARIF_MIME_TYPE,
			templates: presenters.ApplicationSarifTemplatesUfm,
		},
		{
			mimetype:  DEFAULT_MIME_TYPE,
			templates: presenters.DefaultTemplateFilesUfm,
		},
		{
			mimetype:  HTML_MIME_TYPE,
			templates: presenters.ApplicationHTMLTemplatesUfm,
		},
	}
	writerMap := applyTemplatesToWriters(supportedMimeTypes, writers)

	// iterate over all writers and render for each of them
	ctx := invocation.Context()
	availableThreads := semaphore.NewWeighted(threadCount)
	var errMu sync.Mutex
	var errs []error

	for k, v := range writerMap {
		err = availableThreads.Acquire(ctx, 1)
		if err != nil {
			debugLogger.Err(err).Msgf("UFM - [%s] Failed to acquire threading lock. Cancel rendering.", k)
			break
		}

		go func(name string, writer *WriterEntry, results []testapi.TestResult, assetLink string, invocation workflow.InvocationContext) {
			defer availableThreads.Release(1)
			if renderErr := useRendererWithUnifiedModel(name, writer, results, assetLink, invocation); renderErr != nil {
				errMu.Lock()
				errs = append(errs, renderErr)
				errMu.Unlock()
			}
		}(k, v, results, assetLink, invocation)
	}

	// Wait for all goroutines to complete by acquiring all thread slots
	err = availableThreads.Acquire(ctx, threadCount)
	if err != nil {
		debugLogger.Err(err).Msg("UFM - Failed to wait for all threads")
	}

	if len(errs) > 0 {
		combinedErr := errors.Join(errs...)
		debugLogger.Err(combinedErr).Msg("UFM - Errors occurred during parallel rendering")
		return remainingData, combinedErr
	}

	debugLogger.Info().Msgf("UFM - All Rendering done")
	return remainingData, nil
}
