package output_workflow

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var ignoredMimetypes = []string{
	content_type.TEST_SUMMARY,
}

func HandleContentTypeOther(input []workflow.Data, invocation workflow.InvocationContext, writers WriterMap) ([]workflow.Data, error) {
	var finalError error
	debugLogger := invocation.GetEnhancedLogger()

	otherData, output := getOtherResultsFromWorkflowData(input)
	if len(otherData) == 0 {
		debugLogger.Info().Msg("Other - No data to process")
		return output, nil
	}

	supportedMimeTypes := []MimeType2Template{
		{
			mimetype:  SARIF_MIME_TYPE,
			templates: []string{},
		},
		{
			mimetype:  JSON_MIME_TYPE,
			templates: []string{},
		},
		{
			mimetype:  DEFAULT_MIME_TYPE,
			templates: []string{},
		},
	}
	writerMap := applyTemplatesToWriters(supportedMimeTypes, writers)

	usedWriters := make(map[string]bool)

	for _, data := range otherData {
		contentLocation := data.GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Other - Processing '%s' based on '%s' of type '%s'", data.GetIdentifier().String(), contentLocation, data.GetContentType())
		dataWasWritten, err := useWriterWithOther(debugLogger, data, data.GetContentType(), writerMap, usedWriters)
		if !dataWasWritten {
			output = append(output, data)
		}

		if err != nil {
			finalError = errors.Join(finalError, err)
		}
	}

	for name, writer := range writerMap {
		if name == DEFAULT_WRITER && !usedWriters[name] {
			continue
		}
		debugLogger.Info().Msgf("Other - Closing writer: %s", name)
		if err := writer.GetWriter().Close(); err != nil {
			debugLogger.Err(err).Msgf("Other - Failed to close writer: %s", name)
			finalError = errors.Join(finalError, err)
		}
	}

	debugLogger.Info().Msgf("Other - All Rendering done")
	return output, finalError
}

func getOtherResultsFromWorkflowData(input []workflow.Data) ([]workflow.Data, []workflow.Data) {
	var otherData []workflow.Data
	var remainingData []workflow.Data

	for _, data := range input {
		mimeType := data.GetContentType()
		if slices.ContainsFunc(ignoredMimetypes, func(m string) bool { return strings.HasPrefix(mimeType, m) }) {
			remainingData = append(remainingData, data)
			continue
		}
		otherData = append(otherData, data)
	}

	return otherData, remainingData
}

func useWriterWithOther(debugLogger *zerolog.Logger, input workflow.Data, mimeType string, writerMap map[string]*WriterEntry, usedWriters map[string]bool) (bool, error) {
	var finalError error
	dataWasWritten := false

	var singleDataAsString string
	singleData, typeCastSuccessful := input.GetPayload().([]byte)
	if !typeCastSuccessful {
		singleDataAsString, typeCastSuccessful = input.GetPayload().(string)
		if !typeCastSuccessful {
			return dataWasWritten, fmt.Errorf("unsupported output type: %s", mimeType)
		}
	} else {
		singleDataAsString = string(singleData)
	}

	var defaultWriter *WriterEntry
	var defaultWriterName string
	var matchedWriters []*WriterEntry
	var matchedNames []string

	mimeTypeMatches := func(writerMime, dataMime string) bool {
		if writerMime == dataMime {
			return true
		}
		for _, keyword := range []string{"json", "sarif"} {
			if strings.Contains(writerMime, keyword) && strings.Contains(dataMime, keyword) {
				return true
			}
		}
		return false
	}

	for name, writer := range writerMap {
		if mimeTypeMatches(writer.mimeType, mimeType) {
			matchedWriters = append(matchedWriters, writer)
			matchedNames = append(matchedNames, name)
		} else if name == DEFAULT_WRITER {
			defaultWriter = writer
			defaultWriterName = name
		}
	}

	if len(matchedWriters) > 0 {
		for i, writer := range matchedWriters {
			name := matchedNames[i]
			debugLogger.Info().Msgf("Other - Using '%s' writer for: %s", name, mimeType)

			debugLogger.Info().Msgf("Other - [%s] Rendering %s", name, writer.mimeType)
			_, err := fmt.Fprint(writer.GetWriter(), singleDataAsString)
			if err != nil {
				finalError = errors.Join(finalError, err)
			}
			dataWasWritten = true
			usedWriters[name] = true
			debugLogger.Info().Msgf("Other - [%s] Rendering done", name)
		}
	} else if defaultWriter != nil {
		debugLogger.Info().Msgf("Other - No exact mimetype match, using default writer for: %s", mimeType)

		debugLogger.Info().Msgf("Other - [%s] Rendering %s", defaultWriterName, mimeType)
		_, err := fmt.Fprint(defaultWriter.GetWriter(), singleDataAsString)
		if err != nil {
			finalError = errors.Join(finalError, err)
		}
		dataWasWritten = true
		usedWriters[defaultWriterName] = true
		debugLogger.Info().Msgf("Other - [%s] Rendering done", defaultWriterName)
	}

	return dataWasWritten, finalError
}
