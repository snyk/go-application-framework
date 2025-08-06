package networking

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_shouldNotLog(t *testing.T) {
	testCases := []struct {
		name           string
		currentLevel   zerolog.Level
		levelToLogAt   zerolog.Level
		expectedResult bool
	}{
		{
			name:           "CurrentLevelAboveThreshold",
			currentLevel:   zerolog.WarnLevel,
			levelToLogAt:   zerolog.DebugLevel,
			expectedResult: true,
		},
		{
			name:           "CurrentLevelBelowThreshold",
			currentLevel:   zerolog.DebugLevel,
			levelToLogAt:   zerolog.WarnLevel,
			expectedResult: false,
		},
		{
			name:           "CurrentLevelEqualToThreshold",
			currentLevel:   zerolog.InfoLevel,
			levelToLogAt:   zerolog.InfoLevel,
			expectedResult: false,
		},
		{
			name:           "TraceLevelBelowDebug",
			currentLevel:   zerolog.TraceLevel,
			levelToLogAt:   zerolog.DebugLevel,
			expectedResult: false,
		},
		{
			name:           "PanicLevelAboveError",
			currentLevel:   zerolog.PanicLevel,
			levelToLogAt:   zerolog.ErrorLevel,
			expectedResult: true,
		},
		{
			name:           "FatalLevelAboveError",
			currentLevel:   zerolog.FatalLevel,
			levelToLogAt:   zerolog.ErrorLevel,
			expectedResult: true,
		},
		{
			name:           "DisabledLevelAboveAll",
			currentLevel:   zerolog.Disabled,
			levelToLogAt:   zerolog.TraceLevel,
			expectedResult: true,
		},
		{
			name:           "DisabledLevelAboveAll",
			currentLevel:   zerolog.NoLevel,
			levelToLogAt:   zerolog.TraceLevel,
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := shouldNotLog(tc.currentLevel, tc.levelToLogAt)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func Test_LogRequest_NoLog(t *testing.T) {
	buffer := bytes.Buffer{}
	logger := zerolog.New(&buffer).Level(zerolog.InfoLevel)
	request := &http.Request{}

	// method under test
	LogRequest(request, &logger)

	assert.Empty(t, buffer.Bytes())
}

func Test_LogRequest_happyPath_server_request(t *testing.T) {
	expectedBody := "hello world"
	body := io.NopCloser(bytes.NewBufferString(expectedBody))

	logBuffer := bytes.Buffer{}
	logger := zerolog.New(&logBuffer).Level(zerolog.TraceLevel)
	request, err := http.NewRequest(http.MethodGet, "http://localhost/", body)
	assert.NoError(t, err)

	// method under test
	LogRequest(request, &logger)
	assert.Contains(t, logBuffer.String(), expectedBody)

	// ensure that the request body can still be read
	actualBody, err := io.ReadAll(request.Body)
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, string(actualBody))
}

func Test_LogRequest_happyPath_server_request_limited(t *testing.T) {
	inputBody := "this is a longer text, that will not be logged fully. It'll just stop at some point and show the end of the text as well, since start and end of a message might be the most interesting part"
	expectedBody := "this is a longer text, that wi [...shortened...] t be the most interesting part"
	body := io.NopCloser(bytes.NewBufferString(inputBody))

	logBuffer := bytes.Buffer{}
	logger := zerolog.New(&logBuffer).Level(zerolog.TraceLevel)
	request, err := http.NewRequest(http.MethodGet, "http://localhost/", body)
	assert.NoError(t, err)

	// method under test
	LogRequest(request, &logger)
	assert.Contains(t, logBuffer.String(), expectedBody)

	// ensure that the request body can still be read
	actualBody, err := io.ReadAll(request.Body)
	assert.NoError(t, err)
	assert.Equal(t, inputBody, string(actualBody))
}

func Test_LogRequest_happyPath_client_request(t *testing.T) {
	expectedBody := "hello world"
	body := io.NopCloser(bytes.NewBufferString(expectedBody))

	logBuffer := bytes.Buffer{}
	logger := zerolog.New(&logBuffer).Level(zerolog.TraceLevel)
	request, err := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	request.GetBody = func() (io.ReadCloser, error) {
		return body, nil
	}
	assert.NoError(t, err)

	// method under test
	LogRequest(request, &logger)
	assert.Contains(t, logBuffer.String(), expectedBody)
}

func Test_LogRequest_happyPath_gzipped_request(t *testing.T) {
	expectedBody := "hello world"
	gzipBuffer := bytes.NewBuffer([]byte{})
	gzipWriter := gzip.NewWriter(gzipBuffer)
	n, err := gzipWriter.Write([]byte(expectedBody))
	assert.NoError(t, err)
	assert.Greater(t, n, 0)
	err = gzipWriter.Close()
	assert.NoError(t, err)

	logBuffer := bytes.Buffer{}
	logger := zerolog.New(&logBuffer).Level(extendedNetworkLogLevel)
	request, err := http.NewRequest(http.MethodPost, "http://localhost/", gzipBuffer)
	request.Header.Add("Content-Encoding", "gzip")
	assert.NoError(t, err)

	// method under test
	LogRequest(request, &logger)
	assert.Contains(t, logBuffer.String(), expectedBody)
}

func Test_LogResponse_happyPath(t *testing.T) {
	logBuffer := bytes.NewBuffer([]byte{})
	logger := zerolog.New(logBuffer).Level(zerolog.DebugLevel)

	expectedBody := "hello world"
	request := &http.Request{}

	response := &http.Response{}
	response.Request = request
	response.Header = http.Header{}
	response.StatusCode = http.StatusBadGateway
	response.Body = io.NopCloser(bytes.NewBufferString(expectedBody))

	// invoke method under test
	LogResponse(response, &logger)
	assert.Contains(t, logBuffer.String(), expectedBody)

	// ensure the body is still existing after logging it
	actualBody, err := io.ReadAll(response.Body)
	assert.NoError(t, err)
	assert.Equal(t, expectedBody, string(actualBody))
}

func Test_LogResponse_nolog(t *testing.T) {
	logBuffer := bytes.NewBuffer([]byte{})
	logger := zerolog.New(logBuffer).Level(extendedNetworkLogLevel)

	t.Run("nil response", func(t *testing.T) {
		var response *http.Response

		// invoke method under test
		LogResponse(response, &logger)

		actualLoggerContent := logBuffer.String()
		assert.Empty(t, actualLoggerContent)
	})

	t.Run("non trace level logger", func(t *testing.T) {
		response := &http.Response{}
		nonTraceLogger := logger.Level(zerolog.InfoLevel)

		// invoke method under test
		LogResponse(response, &nonTraceLogger)

		actualLoggerContent := logBuffer.String()
		assert.Empty(t, actualLoggerContent)
	})
}

func Test_LogResponse_skipsBinaryContent(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		isBinary    bool
	}{
		{
			name:        "binary/octet-stream",
			contentType: "binary/octet-stream",
			isBinary:    true,
		},
		{
			name:        "text/plain",
			contentType: "text/plain",
			isBinary:    false,
		},
		{
			name:        "application/json",
			contentType: "application/json",
			isBinary:    false,
		},
		{
			name:        "empty content type",
			contentType: "",
			isBinary:    false,
		},
		{
			name:        "case insensitive",
			contentType: "APPLICATION/OCTET-STREAM",
			isBinary:    true,
		},
		{
			name:        "with charset",
			contentType: "application/octet-stream; charset=utf-8",
			isBinary:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := bytes.NewBufferString("")
			logger := zerolog.New(content).Level(zerolog.TraceLevel)

			var testData string
			if tt.isBinary {
				testData = "binary data that should not be logged"
			} else {
				testData = "text data that should be logged"
			}
			response := &http.Response{
				Status:     "200 OK",
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(testData)),
			}
			if tt.contentType != "" {
				response.Header.Set("Content-Type", tt.contentType)
			}

			// Act
			LogResponse(response, &logger)

			logOutput := content.String()
			assert.Contains(t, logOutput, "< response [0x0]: 200 OK")

			if tt.contentType != "" {
				assert.Contains(t, logOutput, "Content-Type:["+tt.contentType+"]")
			}

			if tt.isBinary {
				assert.Contains(t, logOutput, "[BINARY CONTENT - NOT LOGGED]")
				assert.NotContains(t, logOutput, testData)
			} else {
				assert.NotContains(t, logOutput, "[BINARY CONTENT - NOT LOGGED]")
				assert.Contains(t, logOutput, testData)
			}
		})
	}
}

func Test_logRoundTrip(t *testing.T) {
	config := configuration.NewWithOpts()
	expectedResponseBody := "hello client"
	expectedResponseBodyError := "who are you?"
	expectedRequestBody := "hello server"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte(expectedResponseBodyError))
			assert.NoError(t, err)
			return
		}

		_, err := w.Write([]byte(expectedResponseBody))
		assert.NoError(t, err)
	}))
	defer server.Close()

	t.Run("expect body to be logged", func(t *testing.T) {
		logBuffer := bytes.NewBuffer([]byte{})
		logger := zerolog.New(logBuffer).Level(extendedNetworkLogLevel)

		network := NewNetworkAccess(config)
		network.SetLogger(&logger)

		response, err := network.GetHttpClient().Post(server.URL, "text/plain; charset=utf-8", bytes.NewBufferString(expectedRequestBody))
		assert.NoError(t, err)
		assert.NotNil(t, response)

		actualLoggerContent := logBuffer.String()
		assert.NotEmpty(t, actualLoggerContent)
		assert.Contains(t, actualLoggerContent, expectedResponseBody)
		assert.Contains(t, actualLoggerContent, expectedRequestBody)

		t.Log(actualLoggerContent)
	})

	t.Run("expect no body to be logged", func(t *testing.T) {
		logBuffer := bytes.NewBuffer([]byte{})
		logger := zerolog.New(logBuffer).Level(defaultNetworkLogLevel)

		network := NewNetworkAccess(config)
		network.SetLogger(&logger)

		response, err := network.GetHttpClient().Post(server.URL, "text/plain; charset=utf-8", bytes.NewBufferString(expectedRequestBody))
		assert.NoError(t, err)
		assert.NotNil(t, response)

		actualLoggerContent := logBuffer.String()
		assert.NotEmpty(t, actualLoggerContent)
		assert.NotContains(t, actualLoggerContent, expectedResponseBody)
		assert.NotContains(t, actualLoggerContent, expectedRequestBody)

		t.Log(actualLoggerContent)
	})

	t.Run("info level logger", func(t *testing.T) {
		logBuffer := bytes.NewBuffer([]byte{})
		logger := zerolog.New(logBuffer).Level(zerolog.InfoLevel)

		network := NewNetworkAccess(config)
		network.SetLogger(&logger)

		response, err := network.GetHttpClient().Post(server.URL, "text/plain; charset=utf-8", bytes.NewBufferString(expectedRequestBody))
		assert.NoError(t, err)
		assert.NotNil(t, response)

		actualLoggerContent := logBuffer.String()
		assert.Empty(t, actualLoggerContent)
	})

	t.Run("debug level logger for error response", func(t *testing.T) {
		logBuffer := bytes.NewBuffer([]byte{})
		logger := zerolog.New(logBuffer).Level(zerolog.DebugLevel)

		network := NewNetworkAccess(config)
		network.SetLogger(&logger)

		response, err := network.GetHttpClient().Post(server.URL+"/error", "text/plain; charset=utf-8", bytes.NewBufferString(expectedRequestBody))
		assert.NoError(t, err)
		assert.NotNil(t, response)

		actualLoggerContent := logBuffer.String()
		assert.NotEmpty(t, actualLoggerContent)
		assert.Contains(t, actualLoggerContent, expectedResponseBodyError)
	})
}
