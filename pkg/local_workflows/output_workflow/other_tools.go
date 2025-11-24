package output_workflow

import (
	"errors"
	"fmt"
	"slices"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var ignoredMimetypes = []string{
	content_type.TEST_SUMMARY,
}

func HandleContentTypeOther(input []workflow.Data, invocation workflow.InvocationContext, writers WriterMap) ([]workflow.Data, error) {
	var finalError error
	output := []workflow.Data{}
	debugLogger := invocation.GetEnhancedLogger()
	otherHandlerMimetypes := []string{DEFAULT_MIME_TYPE, JSON_MIME_TYPE, SARIF_MIME_TYPE}

	for i := range input {
		mimeType := input[i].GetContentType()
		if slices.Contains(ignoredMimetypes, mimeType) {
			continue
		}

		contentLocation := input[i].GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Other - Processing '%s' based on '%s' of type '%s'", input[i].GetIdentifier().String(), contentLocation, mimeType)
		dataWasWritten, err := useWriterWithOther(debugLogger, input[i], mimeType, writers, otherHandlerMimetypes)
		if !dataWasWritten {
			output = append(output, input[i])
		}

		if err != nil {
			finalError = errors.Join(finalError, err)
		}

	}
	return output, finalError
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

		debugLogger.Info().Msgf("Other - Using Writer for: %s", mimetype)
		for _, w := range writer {
			_, err := fmt.Fprint(w.GetWriter(), singleDataAsString)
			if err != nil {
				finalError = errors.Join(finalError, err)
			}
			dataWasWritten = true
		}
	}

	return dataWasWritten, finalError
}
