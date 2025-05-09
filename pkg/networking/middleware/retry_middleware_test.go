package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/cenkalti/backoff/v5"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Helper to create a response
func newResponse(statusCode int, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}

	localUrl, err := url.Parse("http://example.com")
	if err != nil {
		return nil
	}

	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Request:    &http.Request{Method: http.MethodGet, URL: localUrl}, // Mock request for context
	}
}

type failRoundtripper struct {
	actualCount                  uint
	NumberOfAttemptsUntilSuccess uint
	Error                        error
	ExpectedBody                 []byte
	t                            *testing.T
}

func (f *failRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.actualCount++
	f.t.Helper()
	f.t.Logf("%s: roundtrip", time.Now())

	headers := http.Header{}
	bodyBytes, err := io.ReadAll(req.Body)
	assert.NoError(f.t, err)

	if len(f.ExpectedBody) > 0 {
		assert.Equal(f.t, f.ExpectedBody, bodyBytes)
	}

	if f.actualCount < f.NumberOfAttemptsUntilSuccess {
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: headers}, f.Error
	}

	return &http.Response{StatusCode: http.StatusOK, Header: headers}, f.Error
}

func TestNewRetryMiddleware(t *testing.T) {
	expectedBody := []byte("hello")
	logger := zerolog.Nop()

	t.Run("Happy path, no retry required", func(t *testing.T) {
		var expectedAttempts uint = 1
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: expectedAttempts,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRetryCount, 3)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Happy path, retry resolves successfully", func(t *testing.T) {
		var expectedAttempts uint = 3
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: expectedAttempts,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRetryCount, int(expectedAttempts))
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
		assert.Equal(t, fmt.Sprintf("%d", expectedAttempts), response.Header.Get(retryCountHeaderKey))
	})

	t.Run("Unhappy path, retries didn't resolve the issue", func(t *testing.T) {
		var expectedAttempts uint = 3
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRetryCount, int(expectedAttempts))
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Unhappy path, non default values", func(t *testing.T) {
		var expectedAttempts uint = 2
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRetryCount, int(expectedAttempts))
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Unhappy path, no retries", func(t *testing.T) {
		var expectedAttempts uint = 1
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRetryCount, int(expectedAttempts))
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Unhappy path, lower level failure, no retries", func(t *testing.T) {
		expectedErr := errors.New("blabla")
		var expectedAttempts uint = 1

		failureRoundtripper := &failRoundtripper{Error: expectedErr, t: t}
		config := configuration.NewWithOpts()
		testRequest := httptest.NewRequest(http.MethodGet, "/", nil)

		// invoke system under test
		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		_, err := sut.RoundTrip(testRequest)

		assert.Equal(t, expectedErr.Error(), err.Error())
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})
}

func Test_shouldRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		response          *http.Response
		defaultRetryDelay int
		expectedErrorIs   error
		expectedRetryable *backoff.RetryAfterError // For checking RetryAfter duration
		expectNilError    bool
	}{
		{
			name:              "Retryable status code (429) with Retry-After header",
			response:          newResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"5"}}),
			defaultRetryDelay: 2,
			expectedRetryable: &backoff.RetryAfterError{Duration: 5 * time.Second},
		},
		{
			name:              "Retryable status code (503) with invalid Retry-After header",
			response:          newResponse(http.StatusServiceUnavailable, http.Header{"Retry-After": []string{"abc"}}),
			defaultRetryDelay: 3,
			expectedRetryable: &backoff.RetryAfterError{Duration: 3 * time.Second}, // Uses default
		},
		{
			name:              "Retryable status code (500) without Retry-After header",
			response:          newResponse(http.StatusInternalServerError, nil),
			defaultRetryDelay: 4,
			expectedErrorIs:   errRetryNecessary,
		},
		{
			name:              "Non-retryable status code (200)",
			response:          newResponse(http.StatusOK, nil),
			defaultRetryDelay: 2,
			expectNilError:    true,
		},
		{
			name:              "Non-retryable status code (400)",
			response:          newResponse(http.StatusBadRequest, nil),
			defaultRetryDelay: 2,
			expectNilError:    true,
		},
		{
			name:              "Retryable status code (502) with Retry-After: 0",
			response:          newResponse(http.StatusBadGateway, http.Header{"Retry-After": []string{"0"}}),
			defaultRetryDelay: 2,
			expectedErrorIs:   errRetryNecessary, // retryDelaySecs will be 0
		},
		{
			name:              "Retryable status code (504) with Retry-After: -1",
			response:          newResponse(http.StatusGatewayTimeout, http.Header{"Retry-After": []string{"-1"}}),
			defaultRetryDelay: 2,
			expectedErrorIs:   errRetryNecessary, // retryDelaySecs will be -1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := shouldRetry(tt.response, tt.defaultRetryDelay)

			if tt.expectNilError {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
				if tt.expectedErrorIs != nil {
					assert.True(t, errors.Is(err, tt.expectedErrorIs), "Expected error to be of type %T, got %T (%v)", tt.expectedErrorIs, err, err)
				}
				if tt.expectedRetryable != nil {
					var actualRetryableErr *backoff.RetryAfterError
					isRetryable := errors.As(err, &actualRetryableErr)
					assert.True(t, isRetryable, "Expected error to be a *backoff.RetryableError")
					if isRetryable {
						assert.Equal(t, tt.expectedRetryable, actualRetryableErr, "RetryAfter duration mismatch")
					}
				}
			}
		})
	}
}
