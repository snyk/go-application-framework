package output_workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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

type WriterEntry struct {
	writer    io.Writer
	mimeType  string
	templates []string
	closer    func() error
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

func getWritersToUse(config configuration.Configuration, outputDestination iUtils.OutputDestination, findings []*local_models.LocalFinding) (map[string]*WriterEntry, error) {
	writerMap := map[string]*WriterEntry{
		DEFAULT_WRITER: {
			writer:    outputDestination.GetWriter(),
			mimeType:  presenters.DefaultMimeType,
			templates: presenters.DefaultTemplateFiles,
			closer: func() error {
				_, err := fmt.Fprintln(outputDestination.GetWriter(), "")
				return err
			},
		},
	}

	sarifWriter, err := getSarifFileRenderer(config, findings)
	if err != nil {
		return writerMap, err
	}

	if sarifWriter != nil {
		writerMap[OUTPUT_CONFIG_KEY_SARIF_FILE] = sarifWriter
	}

	if config.GetBool(OUTPUT_CONFIG_KEY_SARIF) {
		writerMap[DEFAULT_WRITER].mimeType = presenters.ApplicationSarifMimeType
		writerMap[DEFAULT_WRITER].templates = presenters.ApplicationSarifTemplates
	}

	if config.IsSet(OUTPUT_CONFIG_TEMPLATE_FILE) {
		writerMap[DEFAULT_WRITER].templates = []string{config.GetString(OUTPUT_CONFIG_TEMPLATE_FILE)}
	}

	return writerMap, nil
}

func getSarifFileRenderer(config configuration.Configuration, findings []*local_models.LocalFinding) (*WriterEntry, error) {
	outputFileName := config.GetString(OUTPUT_CONFIG_KEY_SARIF_FILE)
	if len(outputFileName) == 0 {
		//nolint:nilnil // returning a nil writer is a valid case based on the configuration and is not an error case
		return nil, nil
	}

	if !config.GetBool(OUTPUT_CONFIG_WRITE_EMPTY_FILE) && getTotalNumberOfFindings(findings) == 0 {
		//nolint:nilnil // returning a nil writer is a valid case based on the configuration and is not an error case
		return nil, nil
	}

	file, fileErr := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE, 0644)
	if fileErr != nil {
		return nil, fileErr
	}

	writer := &WriterEntry{
		writer:    file,
		mimeType:  presenters.ApplicationSarifMimeType,
		templates: presenters.ApplicationSarifTemplates,
		closer:    func() error { return file.Close() },
	}
	return writer, nil
}

func useRendererWith(name string, wEntry *WriterEntry, debugLogger *zerolog.Logger, findings []*local_models.LocalFinding, config configuration.Configuration, invocation workflow.InvocationContext) {
	debugLogger.Info().Msgf("[%s] Creating findings model renderer", name)

	if wEntry.closer != nil {
		defer func() {
			closeErr := wEntry.closer()
			if closeErr != nil {
				debugLogger.Err(closeErr).Msgf("[%s] Error while closing writer.", name)
			}
		}()
	}

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
	debugLogger := invocation.GetEnhancedLogger()
	config := invocation.GetConfiguration()

	findings, remainingData := getListOfFindings(input, debugLogger)
	if len(findings) == 0 {
		debugLogger.Info().Msg("No findings to process")
		return input, nil
	}

	threadCount := max(int64(config.GetInt(configuration.MAX_THREADS)), 1)
	debugLogger.Info().Msgf("Thread count: %d", threadCount)

	writerMap, err := getWritersToUse(config, outputDestination, findings)
	if err != nil {
		debugLogger.Err(err).Msg("Failed to initialize all required writers")
	}

	// iterate over all writers and render for each of them
	ctx := context.Background()
	availableThreads := semaphore.NewWeighted(threadCount)
	for k, v := range writerMap {
		err = availableThreads.Acquire(ctx, 1)
		if err != nil {
			debugLogger.Err(err).Msgf("[%s] Failed to acquire threading lock.", k)
		}

		go func() {
			defer availableThreads.Release(1)
			useRendererWith(k, v, debugLogger, findings, config, invocation)
		}()
	}

	err = availableThreads.Acquire(ctx, threadCount)
	if err != nil {
		debugLogger.Err(err).Msg("Failed to wait for all threads")
	}

	debugLogger.Info().Msgf("All Rendering done")
	return remainingData, nil
}
