package output_workflow

import (
	"context"

	"github.com/snyk/go-application-framework/internal/presenters"
	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/sync/semaphore"
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

func useRendererWithUnifiedModel(name string, wEntry *WriterEntry, results []testapi.TestResult, invocation workflow.InvocationContext) {
	debugLogger := invocation.GetEnhancedLogger()

	if !wEntry.renderEmptyData && getTotalNumberOfUnifiedFindings(results) == 0 {
		debugLogger.Info().Msgf("[%s] The input is empty, skipping rendering!", name)
		return
	}

	debugLogger.Info().Msgf("[%s] Creating UFM renderer", name)

	defer func() {
		closeErr := wEntry.writer.Close()
		if closeErr != nil {
			debugLogger.Err(closeErr).Msgf("[%s] Error while closing writer.", name)
		}
	}()

	config := invocation.GetConfiguration()
	renderer := presenters.NewUfmRenderer(
		results,
		config,
		wEntry.writer,
		presenters.UfmWithRuntimeInfo(invocation.GetRuntimeInfo()),
	)

	debugLogger.Info().Msgf("[%s] Rendering %s with %s", name, wEntry.mimeType, wEntry.templates)
	err := renderer.RenderTemplate(wEntry.templates, wEntry.mimeType)
	if err != nil {
		debugLogger.Warn().Err(err).Msgf("[%s] Failed to render local finding", name)
		return
	}

	debugLogger.Info().Msgf("[%s] Rendering done", name)
}

func getTestResultsFromWorkflowData(input []workflow.Data) ([]testapi.TestResult, []workflow.Data) {
	var results []testapi.TestResult
	remainingData := []workflow.Data{}

	for _, data := range input {
		tmp := ufm.GetTestResults(data)
		if tmp != nil {
			results = append(results, tmp...)
			continue
		}
		remainingData = append(remainingData, data)
	}

	return results, remainingData
}

// HandleContentTypeUnifiedModel handles the unified model content type.
func HandleContentTypeUnifiedModel(input []workflow.Data, invocation workflow.InvocationContext, outputDestination iUtils.OutputDestination) ([]workflow.Data, error) {
	var err error
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	// Extract TestResults from workflow data
	results, remainingData := getTestResultsFromWorkflowData(input)
	if len(results) == 0 {
		debugLogger.Info().Msg("No UFM to process")
		return input, nil
	}

	writerMap := getWritersToUse(config, outputDestination)
	if len(writerMap) == 0 {
		debugLogger.Info().Msg("No writers to use")
		return input, nil
	}

	threadCount := max(int64(config.GetInt(configuration.MAX_THREADS)), 1)
	debugLogger.Info().Msgf("Thread count: %d", threadCount)

	// iterate over all writers and render for each of them
	ctx := context.Background()
	availableThreads := semaphore.NewWeighted(threadCount)
	for k, v := range writerMap {
		err = availableThreads.Acquire(ctx, 1)
		if err != nil {
			debugLogger.Err(err).Msgf("[%s] Failed to acquire threading lock. Cancel rendering.", k)
			break
		}

		go func(name string, writer *WriterEntry) {
			defer availableThreads.Release(1)
			useRendererWithUnifiedModel(name, writer, results, invocation)
		}(k, v)
	}

	err = availableThreads.Acquire(ctx, threadCount)
	if err != nil {
		debugLogger.Err(err).Msg("Failed to wait for all threads")
	}

	debugLogger.Info().Msgf("All Rendering done")
	return remainingData, nil
}
