package output_workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"

	"github.com/snyk/go-application-framework/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func getListOfFindings(input []workflow.Data, debugLogger *zerolog.Logger) (findings []*local_models.LocalFinding, remainingData []workflow.Data) {
	findings = []*local_models.LocalFinding{}
	remainingData = []workflow.Data{}

	for i := range input {
		if !strings.HasPrefix(input[i].GetContentType(), content_type.LOCAL_FINDING_MODEL) {
			remainingData = append(remainingData, input[i])
			continue
		}
		debugLogger.Info().Msgf("LFM - [%s] Handling findings model", input[i].GetIdentifier().String())
		var localFindingsModel local_models.LocalFinding
		localFindingsBytes, ok := input[i].GetPayload().([]byte)
		if !ok {
			debugLogger.Warn().Err(fmt.Errorf("invalid payload type: %T", input[i].GetPayload()))
			continue
		}

		err := json.Unmarshal(localFindingsBytes, &localFindingsModel)
		if err != nil {
			debugLogger.Warn().Err(err).Msg("LFM - Failed to unmarshal local finding")
			continue
		}
		findings = append(findings, &localFindingsModel)
	}
	return findings, remainingData
}

func getTotalNumberOfFindings(findings []*local_models.LocalFinding) uint32 {
	if findings == nil {
		return 0
	}

	var count uint32
	for i := range findings {
		count = count + findings[i].Summary.Counts.Count
	}
	return count
}

func useRendererWith(name string, wEntry *WriterEntry, findings []*local_models.LocalFinding, invocation workflow.InvocationContext) {
	debugLogger := invocation.GetEnhancedLogger()

	if !wEntry.renderEmptyData && getTotalNumberOfFindings(findings) == 0 {
		debugLogger.Info().Msgf("LFM - [%s] The input is empty, skipping rendering!", name)
		return
	}

	debugLogger.Info().Msgf("LFM - [%s] Creating findings model renderer", name)

	defer func() {
		closeErr := wEntry.writer.Close()
		if closeErr != nil {
			debugLogger.Err(closeErr).Msgf("LFM - [%s] Error while closing writer.", name)
		}
	}()

	config := invocation.GetConfiguration()
	renderer := presenters.NewLocalFindingsRenderer(
		findings,
		config,
		wEntry.writer,
		presenters.WithRuntimeInfo(invocation.GetRuntimeInfo()),
	)

	debugLogger.Info().Msgf("LFM - [%s] Rendering %s with %s", name, wEntry.mimeType, wEntry.templates)
	err := renderer.RenderTemplate(wEntry.templates, wEntry.mimeType)
	if err != nil {
		debugLogger.Warn().Err(err).Msgf("LFM - [%s] Failed to render local finding", name)
		return
	}

	debugLogger.Info().Msgf("LFM - [%s] Rendering done", name)
}

func HandleContentTypeFindingsModel(input []workflow.Data, invocation workflow.InvocationContext, writers WriterMap) ([]workflow.Data, error) {
	var err error
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	findings, remainingData := getListOfFindings(input, debugLogger)
	if len(findings) == 0 {
		debugLogger.Info().Msg("LFM - No findings to process")
		return input, nil
	}

	threadCount := max(int64(config.GetInt(configuration.MAX_THREADS)), 1)
	debugLogger.Info().Msgf("LFM - Thread count: %d", threadCount)

	supportedMimeTypes := []MimeType2Template{
		{
			mimetype:  SARIF_MIME_TYPE,
			templates: ApplicationSarifTemplates,
		},
		{
			mimetype:  DEFAULT_MIME_TYPE,
			templates: DefaultTemplateFiles,
		},
	}
	writerMap := applyTemplatesToWriters(supportedMimeTypes, writers)

	// iterate over all writers and render for each of them
	ctx := context.Background()
	availableThreads := semaphore.NewWeighted(threadCount)
	for k, v := range writerMap {
		err = availableThreads.Acquire(ctx, 1)
		if err != nil {
			debugLogger.Err(err).Msgf("LFM - [%s] Failed to acquire threading lock. Cancel rendering.", k)
			break
		}

		go func(name string, writer *WriterEntry) {
			defer availableThreads.Release(1)
			useRendererWith(name, writer, findings, invocation)
		}(k, v)
	}

	err = availableThreads.Acquire(ctx, threadCount)
	if err != nil {
		debugLogger.Err(err).Msg("LFM - Failed to wait for all threads")
	}

	debugLogger.Info().Msgf("LFM - All Rendering done")
	return remainingData, nil
}
