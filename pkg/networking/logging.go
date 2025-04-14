package networking

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

const defaultNetworkLogLevel = zerolog.DebugLevel

func shouldNotLog(currentLevel zerolog.Level, levelToLogAt zerolog.Level) bool {
	// Don't log if logger level is above the threshold
	return currentLevel > levelToLogAt
}

func getResponseBody(response *http.Response) io.ReadCloser {
	if response.Body != nil {
		bodyBytes, bodyErr := io.ReadAll(response.Body)
		if bodyErr == nil {
			response.Body.Close()
			bodyReader := io.NopCloser(bytes.NewBuffer(bodyBytes))
			response.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			return bodyReader
		}
	}
	return nil
}

func getRequestBody(request *http.Request) io.ReadCloser {
	if request.GetBody != nil {
		bodyReader, bodyErr := request.GetBody()
		if bodyErr != nil {
			return nil
		}
		return bodyReader
	}

	if request.Body != nil {
		bodyBytes, bodyErr := io.ReadAll(request.Body)
		if bodyErr == nil {
			request.Body.Close()
			bodyReader := io.NopCloser(bytes.NewBuffer(bodyBytes))
			request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			return bodyReader
		}
	}

	return nil
}

func decodeBody(bodyBytes []byte, contentEncoding string) (string, error) {
	if contentEncoding == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return "", errors.Wrap(err, "failed to create gzip reader")
		}
		defer reader.Close()
		decodedBytes, err := io.ReadAll(reader)
		if err != nil {
			return "", errors.Wrap(err, "failed to read decoded body")
		}
		return string(decodedBytes), nil
	} else {
		return string(bodyBytes), nil
	}
}

func logBody(logger *zerolog.Logger, logLevel zerolog.Level, logPrefix string, body io.ReadCloser, header http.Header) {
	if body != nil {
		bodyBytes, bodyErr := io.ReadAll(body)
		defer func() {
			closeErr := body.Close()
			if closeErr != nil {
				logger.WithLevel(logLevel).Err(closeErr).Msg("failed to close body")
			}
		}()

		if bodyErr != nil {
			return
		}

		bodyString, err := decodeBody(bodyBytes, header.Get("Content-Encoding"))
		if err != nil {
			logger.WithLevel(logLevel).Err(err).Msgf("%s Failed to decode request body", logPrefix)
		} else if len(bodyString) > 0 {
			logger.WithLevel(logLevel).Msgf("%s body: %v", logPrefix, bodyString)
		}
	}
}

func LogRequest(r *http.Request, logger *zerolog.Logger) {
	if shouldNotLog(logger.GetLevel(), defaultNetworkLogLevel) { // Don't log if logger level is above the threshold
		return
	}

	logPrefixRequest := fmt.Sprintf("> request [%p]:", r)
	logger.WithLevel(defaultNetworkLogLevel).Msgf("%s %s %s", logPrefixRequest, r.Method, r.URL.String())
	logger.WithLevel(defaultNetworkLogLevel).Msgf("%s header: %v", logPrefixRequest, r.Header)

	// additional logs for trace level logging
	if shouldNotLog(logger.GetLevel(), zerolog.TraceLevel) {
		return
	}

	logBody(logger, defaultNetworkLogLevel, logPrefixRequest, getRequestBody(r), r.Header)
}

func LogResponse(response *http.Response, logger *zerolog.Logger) {
	if shouldNotLog(logger.GetLevel(), defaultNetworkLogLevel) { // Don't log if logger level is above the threshold
		return
	}

	if response != nil {
		logPrefixResponse := fmt.Sprintf("< response [%p]:", response.Request)
		logger.WithLevel(defaultNetworkLogLevel).Msgf("%s %s", logPrefixResponse, response.Status)
		logger.WithLevel(defaultNetworkLogLevel).Msgf("%s header: %v", logPrefixResponse, response.Header)

		// additional logs for trace level logging and error responses
		if !(response.StatusCode >= 400 || !shouldNotLog(logger.GetLevel(), zerolog.TraceLevel)) {
			return
		}

		logBody(logger, defaultNetworkLogLevel, logPrefixResponse, getResponseBody(response), response.Header)
	}
}
