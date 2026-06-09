package networking

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

const defaultNetworkLogLevel = zerolog.DebugLevel
const extendedNetworkLogLevel = zerolog.TraceLevel
const maxNumberOfRequestBodyCharacters = 60
const maxNumberOfResponseBodyCharacters = 10 * 1024 // 10KiB, to ensure we don't log an entire CLI download response that is interrupted.

// Binary content types that should not have their response bodies logged to avoid memory issues
var binaryMIMETypes = []string{
	"application/octet-stream",  // Standard binary MIME type
	"binary/octet-stream",       // Non-standard but sometimes used
	"application/zip",           // ZIP archives
	"application/gzip",          // GZIP archives
	"application/x-gzip",        // Alternative GZIP MIME type
	"application/x-tar",         // TAR archives
	"application/x-executable",  // Executable files
	"application/x-msdownload",  // Windows executables
	"application/x-mach-binary", // macOS binaries
	"application/x-elf",         // Linux ELF binaries
}

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

func logBody(logger *zerolog.Logger, logLevel zerolog.Level, logPrefix string, body io.ReadCloser, header http.Header, maxBodyCharacters int64) {
	if body != nil {
		defer func() {
			closeErr := body.Close()
			if closeErr != nil {
				logger.WithLevel(logLevel).Err(closeErr).Msg("failed to close body")
			}
		}()

		bodyBytes, bodyErr := io.ReadAll(body)
		if bodyErr != nil {
			return
		}

		bodyString, err := decodeBody(bodyBytes, header.Get("Content-Encoding"))
		if err != nil {
			logger.WithLevel(logLevel).Err(err).Msgf("%s Failed to decode request body", logPrefix)
		} else if len(bodyString) > 0 {
			bodyString = shortenStringFromCenter(bodyString, maxBodyCharacters)
			logger.WithLevel(logLevel).Msgf("%s body: %v", logPrefix, bodyString)
		}
	}
}

// shortenStringFromCenter shortens the given string and keeps only maxCharacters of it. It removes content from the center
// of the string and adds a placeholder making this obvious.
func shortenStringFromCenter(str string, maxCharacters int64) string {
	// shorten body if maxBodyCharacters is set
	bodyLength := int64(len(str))
	if maxCharacters > 0 && bodyLength > maxCharacters {
		subLength := maxCharacters / 2
		str = fmt.Sprintf("%s [...shortened...] %s", str[0:subLength], str[bodyLength-subLength:bodyLength])
	}
	return str
}

// isBinaryContent checks if the content type indicates binary data that shouldn't be logged
func isBinaryContent(contentType string) bool {
	mimeType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	for _, binaryMIMEType := range binaryMIMETypes {
		if mimeType == binaryMIMEType {
			return true
		}
	}
	return false
}

func LogRequest(r *http.Request, logger *zerolog.Logger) {
	if shouldNotLog(logger.GetLevel(), defaultNetworkLogLevel) { // Don't log if logger level is above the threshold
		return
	}

	logPrefixRequest := fmt.Sprintf("> request [%p]:", r)
	logger.WithLevel(defaultNetworkLogLevel).Msgf("%s %s %s", logPrefixRequest, r.Method, r.URL.String())
	logger.WithLevel(defaultNetworkLogLevel).Msgf("%s header: %v", logPrefixRequest, r.Header)

	// additional logs for trace level logging
	if shouldNotLog(logger.GetLevel(), extendedNetworkLogLevel) {
		return
	}

	logBody(logger, defaultNetworkLogLevel, logPrefixRequest, getRequestBody(r), r.Header, maxNumberOfRequestBodyCharacters)
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
		if !(response.StatusCode >= 400 || !shouldNotLog(logger.GetLevel(), extendedNetworkLogLevel)) {
			return
		}

		// Skip response body logging for binary content to avoid memory issues with large binary downloads.
		if isBinaryContent(response.Header.Get("Content-Type")) {
			logger.WithLevel(defaultNetworkLogLevel).Msgf("%s body: [BINARY CONTENT - NOT LOGGED]", logPrefixResponse)
			return
		}

		logBody(logger, defaultNetworkLogLevel, logPrefixResponse, getResponseBody(response), response.Header, maxNumberOfResponseBodyCharacters)
	}
}
