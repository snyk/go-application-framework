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

func getDefaultWriterUfm(config configuration.Configuration, outputDestination iUtils.OutputDestination) *WriterEntry {
	writer := &WriterEntry{
		writer: &newLineCloser{
			writer: outputDestination.GetWriter(),
		},
		mimeType:        SARIF_MIME_TYPE,
		templates:       presenters.ApplicationSarifTemplatesUfm,
		renderEmptyData: true,
	}

	if config.GetBool(OUTPUT_CONFIG_KEY_SARIF) {
		writer.mimeType = SARIF_MIME_TYPE
		writer.templates = presenters.ApplicationSarifTemplatesUfm
	}

	if config.IsSet(OUTPUT_CONFIG_TEMPLATE_FILE) {
		writer.templates = []string{config.GetString(OUTPUT_CONFIG_TEMPLATE_FILE)}
	}

	return writer
}

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
		tmp := ufm.GetTestResultsFromWorkflowData(data)
		if tmp != nil {
			results = append(results, tmp...)
			continue
		}
		remainingData = append(remainingData, data)
	}

	return results, remainingData
}

func getWritersToUseUfm(config configuration.Configuration, outputDestination iUtils.OutputDestination) map[string]*WriterEntry {
	// resulting map of writers and their templates
	writerMap := map[string]*WriterEntry{}

	// currently the only used default writer is sarif
	if tmp := getDefaultWriterUfm(config, outputDestination); tmp != nil {
		writerMap[DEFAULT_WRITER] = tmp
	}

	// default file writers
	fileWriters := []FileWriter{
		{
			OUTPUT_CONFIG_KEY_SARIF_FILE,
			SARIF_MIME_TYPE,
			presenters.ApplicationSarifTemplatesUfm,
			true,
		},
		/*
			skipping support for json file output by default, since there is no supporting rendering yet.
			{
				OUTPUT_CONFIG_KEY_JSON_FILE,
				SARIF_MIME_TYPE,
				ApplicationSarifTemplates,
				true,
			},*/
	}

	// use configured file writers if available
	if tmp, ok := config.Get(OUTPUT_CONFIG_KEY_FILE_WRITERS).([]FileWriter); ok {
		fileWriters = tmp
	}

	for _, fileWriter := range fileWriters {
		if config.IsSet(fileWriter.NameConfigKey) {
			writerMap[fileWriter.NameConfigKey] = &WriterEntry{
				writer:          &delayedFileOpenWriteCloser{Filename: config.GetString(fileWriter.NameConfigKey)},
				mimeType:        fileWriter.MimeType,
				templates:       fileWriter.TemplateFiles,
				renderEmptyData: fileWriter.WriteEmptyContent,
			}
		}
	}

	return writerMap
}

// HandleContentTypeUnifiedModel handles the unified model content type.
func HandleContentTypeUnifiedModel(input []workflow.Data, invocation workflow.InvocationContext, outputDestination iUtils.OutputDestination) ([]workflow.Data, error) {
	var err error
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	// Extract TestResults from workflow data
	results, remainingData := getTestResultsFromWorkflowData(input)
	if len(results) == 0 {
		debugLogger.Info().Msg("No UFM data to process")
		return remainingData, nil
	}

	writerMap := getWritersToUseUfm(config, outputDestination)
	if len(writerMap) == 0 {
		debugLogger.Info().Msg("No UFM writers to use")
		return remainingData, nil
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
