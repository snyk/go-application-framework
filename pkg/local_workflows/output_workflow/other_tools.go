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
	otherHandlerMimetypes := []string{DEFAULT_MIME_TYPE, JSON_MIME_TYPE, SARIF_MIME_TYPE}

	otherData, output := getOtherResultsFromWorkflowData(input)
	if len(otherData) == 0 {
		debugLogger.Info().Msg("Other - No data to process")
		return output, nil
	}

	for _, data := range otherData {
		contentLocation := data.GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Other - Processing '%s' based on '%s' of type '%s'", data.GetIdentifier().String(), contentLocation, data.GetContentType())
		dataWasWritten, err := useWriterWithOther(debugLogger, data, data.GetContentType(), writers, otherHandlerMimetypes)
		if !dataWasWritten {
			output = append(output, data)
		}

		if err != nil {
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

func useWriterWithOther(debugLogger *zerolog.Logger, input workflow.Data, mimeType string, writers WriterMap, supportedMimeTypes []string) (bool, error) {
	var finalError error
	dataWasWritten := false
	// try to convert payload to a string
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

	for _, mimetype := range supportedMimeTypes {
		writer := writers.PopWritersByMimetype(mimetype)
		if len(writer) == 0 {
			debugLogger.Info().Msgf("Other - No writer found for: %s", mimetype)
			continue
		}

		for _, w := range writer {
			debugLogger.Info().Msgf("Other - Using '%s' writer for: %s", w.name, mimetype)
			defer func() {
				if err := w.GetWriter().Close(); err != nil {
					debugLogger.Err(err).Msgf("Other - [%s] Failed to close writer for: %s", w.name, mimetype)
				}
			}()
			debugLogger.Info().Msgf("Other -[%s] Rendering %s", w.name, w.mimeType)
			_, err := fmt.Fprint(w.GetWriter(), singleDataAsString)
			if err != nil {
				finalError = errors.Join(finalError, err)
			}
			dataWasWritten = true
			debugLogger.Info().Msgf("Other - [%s] Rendering done", w.name)
		}
	}

	return dataWasWritten, finalError
}
