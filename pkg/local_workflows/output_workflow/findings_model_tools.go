package output_workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"

	"github.com/snyk/go-application-framework/internal/presenters"
	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// WriterEntry is an internal structure to handle all template based writers
type WriterEntry struct {
	writer          io.WriteCloser
	mimeType        string
	templates       []string
	renderEmptyData bool
}

// FileWriter is a public structure used to configure file based rendering
type FileWriter struct {
	NameConfigKey     string   // defines the configuration key to look up the filename under
	MimeType          string   // defines the final mime type of the rendering
	TemplateFiles     []string // defines the set of template files to use for rendering
	WriteEmptyContent bool     // specifies if anything should be written at all if the input data is empty
}

func getListOfFindings(input []workflow.Data, debugLogger *zerolog.Logger) (findings []*local_models.LocalFinding, remainingData []workflow.Data) {
	findings = []*local_models.LocalFinding{}
	remainingData = []workflow.Data{}

	for i := range input {
		if !strings.HasPrefix(input[i].GetContentType(), content_type.LOCAL_FINDING_MODEL) {
			remainingData = append(remainingData, input[i])
			continue
		}
		debugLogger.Info().Msgf("[%s] Handling findings model", input[i].GetIdentifier().String())
		var localFindingsModel local_models.LocalFinding
		localFindingsBytes, ok := input[i].GetPayload().([]byte)
		if !ok {
			debugLogger.Warn().Err(fmt.Errorf("invalid payload type: %T", input[i].GetPayload()))
			continue
		}

		err := json.Unmarshal(localFindingsBytes, &localFindingsModel)
		if err != nil {
			debugLogger.Warn().Err(err).Msg("Failed to unmarshal local finding")
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

func getWritersToUse(config configuration.Configuration, outputDestination iUtils.OutputDestination) map[string]*WriterEntry {
	// resulting map of writers and their templates
	writerMap := map[string]*WriterEntry{
		DEFAULT_WRITER: getDefaultWriter(config, outputDestination),
	}

	// default file writers
	fileWriters := []FileWriter{
		{
			OUTPUT_CONFIG_KEY_SARIF_FILE,
			SARIF_MIME_TYPE,
			ApplicationSarifTemplates,
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

func getDefaultWriter(config configuration.Configuration, outputDestination iUtils.OutputDestination) *WriterEntry {
	writer := &WriterEntry{
		writer: &newLineCloser{
			writer: outputDestination.GetWriter(),
		},
		mimeType:        DEFAULT_MIME_TYPE,
		templates:       DefaultTemplateFiles,
		renderEmptyData: true,
	}

	if config.GetBool(OUTPUT_CONFIG_KEY_SARIF) {
		writer.mimeType = SARIF_MIME_TYPE
		writer.templates = ApplicationSarifTemplates
	}

	if config.IsSet(OUTPUT_CONFIG_TEMPLATE_FILE) {
		writer.templates = []string{config.GetString(OUTPUT_CONFIG_TEMPLATE_FILE)}
	}

	return writer
}

func useRendererWith(name string, wEntry *WriterEntry, findings []*local_models.LocalFinding, invocation workflow.InvocationContext) {
	debugLogger := invocation.GetEnhancedLogger()

	if !wEntry.renderEmptyData && getTotalNumberOfFindings(findings) == 0 {
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
	renderer := presenters.NewLocalFindingsRenderer(
		findings,
		config,
		wEntry.writer,
		presenters.WithRuntimeInfo(invocation.GetRuntimeInfo()),
	)

	debugLogger.Info().Msgf("[%s] Rendering %s with %s", name, wEntry.mimeType, wEntry.templates)
	err := renderer.RenderTemplate(wEntry.templates, wEntry.mimeType)
	if err != nil {
		debugLogger.Warn().Err(err).Msgf("[%s] Failed to render local finding", name)
		return
	}

	debugLogger.Info().Msgf("[%s] Rendering done", name)
}

func HandleContentTypeFindingsModel(input []workflow.Data, invocation workflow.InvocationContext, outputDestination iUtils.OutputDestination) ([]workflow.Data, error) {
	var err error
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	findings, remainingData := getListOfFindings(input, debugLogger)
	if len(findings) == 0 {
		debugLogger.Info().Msg("No findings to process")
		return input, nil
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
			useRendererWith(name, writer, findings, invocation)
		}(k, v)
	}

	err = availableThreads.Acquire(ctx, threadCount)
	if err != nil {
		debugLogger.Err(err).Msg("Failed to wait for all threads")
	}

	debugLogger.Info().Msgf("All Rendering done")
	return remainingData, nil
}
