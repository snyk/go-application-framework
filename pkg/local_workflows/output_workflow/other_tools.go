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

var supportedMimeTypes = []string{"sarif", "json", DEFAULT_MIME_TYPE}

func HandleContentTypeOther(input []workflow.Data, invocation workflow.InvocationContext, writers WriterMap) ([]workflow.Data, error) {
	var finalError error
	debugLogger := invocation.GetEnhancedLogger()

	otherData, output := getOtherResultsFromWorkflowData(input)
	if len(otherData) == 0 {
		debugLogger.Info().Msg("Other - No data to process")
		return output, nil
	}

	dataToMimeTypeMap := map[string][]workflow.Data{}

	// map data to mime type
	for _, data := range otherData {
		contentLocation := data.GetContentLocation()
		if len(contentLocation) == 0 {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Other - Processing '%s' based on '%s' of type '%s'", data.GetIdentifier().String(), contentLocation, data.GetContentType())

		dataMimetype := data.GetContentType()
		dataMapped := false

		// filter data based on supportedMimeTypes
		for _, fuzzyType := range supportedMimeTypes {
			if !strings.Contains(dataMimetype, fuzzyType) {
				output = append(output, data)
				continue
			}

			// determine writer mimetype based on fuzzy type
			writerMimetypes := writers.AvailableMimetypes()
			for _, writerMimetype := range writerMimetypes {
				if strings.Contains(writerMimetype, fuzzyType) {
					dataToMimeTypeMap[writerMimetype] = append(dataToMimeTypeMap[writerMimetype], data)
					dataMapped = true
				}
			}
		}

		if !dataMapped {
			dataToMimeTypeMap[DEFAULT_MIME_TYPE] = append(dataToMimeTypeMap[DEFAULT_MIME_TYPE], data)
		}
	}

	// render data based on mimetype
	for mimeType, data := range dataToMimeTypeMap {
		writersToUse := writers.PopWritersByMimetype(mimeType)

		dataWasWritten, err := useWriterWithOther(debugLogger, data, writersToUse)
		if !dataWasWritten {
			output = append(output, data...)
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

func useWriterWithOther(debugLogger *zerolog.Logger, input []workflow.Data, writerMap []*WriterEntry) (bool, error) {
	var finalError error
	dataWasWritten := false

	for _, writer := range writerMap {
		name := writer.name

		defer func() {
			closeErr := writer.writer.Close()
			if closeErr != nil {
				debugLogger.Err(closeErr).Msgf("Other - [%s] Error while closing writer.", name)
			}
		}()

		for _, data := range input {
			mimeType := data.GetContentType()

			var singleDataAsString string
			singleData, typeCastSuccessful := data.GetPayload().([]byte)
			if !typeCastSuccessful {
				singleDataAsString, typeCastSuccessful = data.GetPayload().(string)
				if !typeCastSuccessful {
					return dataWasWritten, fmt.Errorf("unsupported output type: %s", mimeType)
				}
			} else {
				singleDataAsString = string(singleData)
			}

			debugLogger.Info().Msgf("Other - Using '%s' writer for: %s", name, mimeType)

			debugLogger.Info().Msgf("Other - [%s] Rendering %s", name, writer.mimeType)
			_, err := fmt.Fprint(writer.GetWriter(), singleDataAsString)
			if err != nil {
				finalError = errors.Join(finalError, err)
			}
			dataWasWritten = true
			debugLogger.Info().Msgf("Other - [%s] Rendering done", name)
		}
	}

	return dataWasWritten, finalError
}
