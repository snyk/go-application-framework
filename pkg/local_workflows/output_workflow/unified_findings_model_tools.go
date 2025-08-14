package output_workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	presenters "github.com/snyk/go-application-framework/internal/unified_presenters"
	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/sync/semaphore"
)

func getUnifiedProjectResults(input []workflow.Data, debugLogger *zerolog.Logger) ([]*presenters.UnifiedProjectResult, []workflow.Data) {
	var projectResults []*presenters.UnifiedProjectResult
	var remainingData []workflow.Data
	var currentFindingsData *[]testapi.FindingData

	// Each project appears in the order Unified Findings, Unified Summary, then CLI Summary.
	// CLI Summary is ignored and reappended.
	for _, data := range input {
		contentType := data.GetContentType()
		payloadBytes, ok := data.GetPayload().([]byte)
		if !ok {
			debugLogger.Warn().Err(fmt.Errorf("invalid payload type: %T", data.GetPayload())).Msg("Skipping data item in unified model processing")
			remainingData = append(remainingData, data)
			continue
		}

		switch {
		case strings.HasPrefix(contentType, LocalUnifiedFindingModel):
			if currentFindingsData != nil {
				debugLogger.Warn().Msg("Found new findings data before a summary for the previous set. Discarding old findings.")
			}
			var findings []testapi.FindingData
			if err := json.Unmarshal(payloadBytes, &findings); err != nil {
				debugLogger.Warn().Err(err).Msg("Failed to unmarshal unified findings")
				currentFindingsData = nil
			} else {
				currentFindingsData = &findings
			}
		case strings.HasPrefix(contentType, LocalUnifiedSummaryModel):
			if currentFindingsData == nil {
				debugLogger.Warn().Msg("Found summary data without preceding findings data. Ignoring summary.")
				continue
			}

			var summaryPayload presenters.SummaryPayload
			if err := json.Unmarshal(payloadBytes, &summaryPayload); err != nil {
				debugLogger.Warn().Err(err).Msg("Failed to unmarshal unified summary")
				currentFindingsData = nil // Discard associated findings
				continue
			}

			projectResult := &presenters.UnifiedProjectResult{
				Findings:             *currentFindingsData,
				Summary:              summaryPayload.Summary,
				DependencyCount:      summaryPayload.DependencyCount,
				PackageManager:       summaryPayload.PackageManager,
				ProjectName:          summaryPayload.ProjectName,
				DisplayTargetFile:    summaryPayload.DisplayTargetFile,
				UniqueCount:          int(summaryPayload.UniqueCount),
				VulnerablePathsCount: summaryPayload.VulnerablePathsCount,
			}
			projectResults = append(projectResults, projectResult)

			// Reset for the next project
			currentFindingsData = nil
		default:
			remainingData = append(remainingData, data)
		}
	}

	if currentFindingsData != nil {
		debugLogger.Warn().Msg("Found unprocessed findings data at the end of the workflow data, missing a summary.")
	}

	return projectResults, remainingData
}

func getTotalNumberOfUnifiedFindings(projectResults []*presenters.UnifiedProjectResult) int {
	if projectResults == nil {
		return 0
	}

	var count int
	for _, result := range projectResults {
		if result.Summary != nil {
			for _, r := range result.Summary.Results {
				count += r.Total
			}
		}
	}
	return count
}

//func getWritersToUse(config configuration.Configuration, outputDestination OutputDestination) map[string]*WriterEntry {
//	// resulting map of writers and their templates
//	writerMap := map[string]*WriterEntry{
//		DefaultWriter: getDefaultWriter(config, outputDestination),
//	}
//
//	// default file writers
//	var fileWriters []FileWriter
//
//	// use configured file writers if available
//	if tmp, ok := config.Get(OutputConfigKeyFileWriters).([]FileWriter); ok {
//		fileWriters = tmp
//	}
//
//	for _, fileWriter := range fileWriters {
//		if config.IsSet(fileWriter.NameConfigKey) {
//			writerMap[fileWriter.NameConfigKey] = &WriterEntry{
//				writer:          &delayedFileOpenWriteCloser{Filename: config.GetString(fileWriter.NameConfigKey)},
//				mimeType:        fileWriter.MimeType,
//				templates:       fileWriter.TemplateFiles,
//				renderEmptyData: fileWriter.WriteEmptyContent,
//			}
//		}
//	}
//
//	return writerMap
//}

//func getDefaultWriter(config configuration.Configuration, outputDestination OutputDestination) *WriterEntry {
//	writer := &WriterEntry{
//		writer: &newLineCloser{
//			writer: outputDestination.GetWriter(),
//		},
//		mimeType:        DefaultMimeType,
//		templates:       presenters.DefaultTemplateFiles,
//		renderEmptyData: true,
//	}
//
//	if config.IsSet(OutputConfigTemplateFile) {
//		writer.templates = []string{config.GetString(OutputConfigTemplateFile)}
//	}
//
//	return writer
//}

func useRendererWithUnifiedModel(name string, wEntry *WriterEntry, projectResults []*presenters.UnifiedProjectResult, invocation workflow.InvocationContext) {
	debugLogger := invocation.GetEnhancedLogger()

	if !wEntry.renderEmptyData && getTotalNumberOfUnifiedFindings(projectResults) == 0 {
		debugLogger.Info().Msgf("[%s] The input is empty, skipping rendering!", name)
		return
	}

	debugLogger.Info().Msgf("[%s] Creating findings model renderer", name)

	defer func() {
		closeErr := wEntry.writer.Close()
		if closeErr != nil {
			debugLogger.Err(closeErr).Msgf("[%s] Error while closing writer.", name)
		}
	}()

	config := invocation.GetConfiguration()
	renderer := presenters.NewUnifiedFindingsRenderer(
		projectResults,
		config,
		wEntry.writer,
		presenters.WithUnifiedRuntimeInfo(invocation.GetRuntimeInfo()),
	)

	debugLogger.Info().Msgf("[%s] Rendering %s with %s", name, wEntry.mimeType, wEntry.templates)
	err := renderer.RenderTemplate(wEntry.templates, wEntry.mimeType)
	if err != nil {
		debugLogger.Warn().Err(err).Msgf("[%s] Failed to render local finding", name)
		return
	}

	debugLogger.Info().Msgf("[%s] Rendering done", name)
}

// HandleContentTypeUnifiedModel handles the unified model content type.
func HandleContentTypeUnifiedModel(input []workflow.Data, invocation workflow.InvocationContext, outputDestination iUtils.OutputDestination) ([]workflow.Data, error) {
	var err error
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	projectResults, remainingData := getUnifiedProjectResults(input, debugLogger)
	if len(projectResults) == 0 {
		debugLogger.Info().Msg("No complete projects with findings and summary to process")
		return remainingData, nil
	}

	threadCount := max(int64(config.GetInt(configuration.MAX_THREADS)), 1)
	debugLogger.Info().Msgf("Thread count: %d", threadCount)

	writerMap := getWritersToUse(config, outputDestination)

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
			useRendererWithUnifiedModel(name, writer, projectResults, invocation)
		}(k, v)
	}

	err = availableThreads.Acquire(ctx, threadCount)
	if err != nil {
		debugLogger.Err(err).Msg("Failed to wait for all threads")
	}

	debugLogger.Info().Msgf("All Rendering done")
	return remainingData, nil
}
