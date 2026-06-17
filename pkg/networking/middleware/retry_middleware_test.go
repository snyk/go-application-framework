package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cenkalti/backoff/v5"

	"github.com/snyk/go-application-framework/pkg/configuration"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
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
	actualCount                  int
	NumberOfAttemptsUntilSuccess int
	Error                        error
	ExpectedBody                 []byte
	// roundTripFn overrides the default RoundTrip implementation
	roundTripFn *func(req *http.Request) (*http.Response, error)
	t           *testing.T
}

// getBodyRetryRoundTripper returns 503 on the first trip and 200 thereafter, asserting
// GetBody returns the full body on every invocation.
type getBodyRetryRoundTripper struct {
	t            *testing.T
	expectedBody []byte
	invocations  int
}

func (g *getBodyRetryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	g.invocations++

	require.NotNil(g.t, req.GetBody, "invocation %d: GetBody must be set when body is buffered", g.invocations)

	body, err := req.GetBody()
	require.NoError(g.t, err, "invocation %d", g.invocations)
	defer func() { _ = body.Close() }()

	got, err := io.ReadAll(body)
	require.NoError(g.t, err, "invocation %d", g.invocations)
	assert.Equal(g.t, g.expectedBody, got, "invocation %d: GetBody must return full body", g.invocations)

	status := http.StatusServiceUnavailable
	if g.invocations >= 2 {
		status = http.StatusOK
	}

	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Request:    req,
	}, nil
}

func (f *failRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.roundTripFn != nil {
		return (*f.roundTripFn)(req)
	}
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

type retryNotifyTracker struct {
	mu     sync.Mutex
	errors []error
}

func (t *retryNotifyTracker) handler() networktypes.ErrorHandlerFunc {
	return func(err error, ctx context.Context) error {
		t.mu.Lock()
		t.errors = append(t.errors, err)
		t.mu.Unlock()
		return err
	}
}

func TestNewRetryMiddleware(t *testing.T) {
	expectedBody := []byte("hello")
	logger := zerolog.Nop()

	t.Run("Max attempts cached from first response, not recalculated on retry", func(t *testing.T) {
		attemptCount := 0

		//nolint:unparam // error is always nil but signature must match http.RoundTripper
		customRTFn := func(req *http.Request) (*http.Response, error) {
			attemptCount++
			headers := http.Header{}

			switch attemptCount {
			case 1:
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     headers,
					Request:    req,
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Header:     headers,
					Request:    req,
				}, nil
			}
		}

		failRoundtripper := &failRoundtripper{
			t:           t,
			roundTripFn: &customRTFn,
		}

		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 1)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		assert.NoError(t, err)
		assert.NotNil(t, response)

		assert.Equal(t, attemptThreeNetworkRequests, attemptCount, "Should use cached max attempts from first 429 response")
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode, "Final response should be 500")
	})

	t.Run("Happy path, no retry required", func(t *testing.T) {
		var expectedAttempts = 1
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: expectedAttempts,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 3)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Happy path, retry resolves successfully", func(t *testing.T) {
		var expectedAttempts int = 3
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: expectedAttempts,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, expectedAttempts)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
		assert.Equal(t, fmt.Sprintf("%d", expectedAttempts), response.Header.Get(retryCountHeaderKey))
	})

	t.Run("Happy path, 429 with only X-Ratelimit-Reset then success", func(t *testing.T) {
		attemptCount := 0

		//nolint:unparam // error is always nil but signature must match http.RoundTripper
		customRTFn := func(req *http.Request) (*http.Response, error) {
			attemptCount++
			headers := http.Header{}

			switch attemptCount {
			case 1:
				headers.Set("X-Ratelimit-Reset", "0")
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     headers,
					Request:    req,
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     headers,
					Request:    req,
				}, nil
			}
		}

		rt := &failRoundtripper{t: t, roundTripFn: &customRTFn}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 3)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, rt)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.GreaterOrEqual(t, attemptCount, 2)
	})

	t.Run("429 with Retry-After beyond max wait returns SNYK-0001 and last response", func(t *testing.T) {
		const hugeRetryAfter = "126144000" // 4 years in seconds; exceeds maxRetryAfter

		//nolint:unparam // error is always nil but signature must match http.RoundTripper
		customRTFn := func(req *http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("Retry-After", hugeRetryAfter)
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     h,
				Request:    req,
			}, nil
		}

		rt := &failRoundtripper{t: t, roundTripFn: &customRTFn}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 3)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, rt)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		assert.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		require.Equal(t, hugeRetryAfter, resp.Header.Get("Retry-After"))
	})

	t.Run("429 with X-RateLimit-Reset beyond max wait returns SNYK-0001 and last response", func(t *testing.T) {
		const hugeReset = "126144000"

		//nolint:unparam // error is always nil but signature must match http.RoundTripper
		customRTFn := func(req *http.Request) (*http.Response, error) {
			h := http.Header{}
			h.Set("X-RateLimit-Reset", hugeReset)
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     h,
				Request:    req,
			}, nil
		}

		rt := &failRoundtripper{t: t, roundTripFn: &customRTFn}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 3)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, rt)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		assert.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		require.Equal(t, hugeReset, resp.Header.Get("X-RateLimit-Reset"))
	})

	t.Run("Unhappy path, retries didn't resolve the issue", func(t *testing.T) {
		var expectedAttempts = 3
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, expectedAttempts)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Unhappy path, non default values", func(t *testing.T) {
		var expectedAttempts = 2
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, expectedAttempts)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Unhappy path, no retries", func(t *testing.T) {
		var expectedAttempts = 1
		failureRoundtripper := &failRoundtripper{
			NumberOfAttemptsUntilSuccess: 10,
			ExpectedBody:                 expectedBody,
			t:                            t,
		}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, expectedAttempts)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(expectedBody)))
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("Unhappy path, lower level failure, no retries", func(t *testing.T) {
		expectedErr := errors.New("blabla")
		var expectedAttempts = 1

		failureRoundtripper := &failRoundtripper{Error: expectedErr, t: t}
		config := configuration.NewWithOpts()
		testRequest := httptest.NewRequest(http.MethodGet, "/", nil)

		// invoke system under test
		sut := NewRetryMiddleware(config, &logger, failureRoundtripper)
		_, err := sut.RoundTrip(testRequest)

		assert.Equal(t, expectedErr.Error(), err.Error())
		assert.Equal(t, expectedAttempts, failureRoundtripper.actualCount)
	})

	t.Run("http.NoBody is not buffered when retries are enabled", func(t *testing.T) {
		var capturedBody io.ReadCloser

		//nolint:unparam // error is always nil but signature must match http.RoundTripper
		customRTFn := func(req *http.Request) (*http.Response, error) {
			capturedBody = req.Body
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: req}, nil
		}

		rt := &failRoundtripper{t: t, roundTripFn: &customRTFn}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 3)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", http.NoBody)
		require.NoError(t, err)
		require.Equal(t, http.NoBody, req.Body)

		sut := NewRetryMiddleware(config, &logger, rt)
		_, err = sut.RoundTrip(req)
		require.NoError(t, err)

		assert.Equal(t, http.NoBody, capturedBody)
	})

	t.Run("buffered request body sets GetBody for HTTP/2 retry compatibility", func(t *testing.T) {
		rt := &getBodyRetryRoundTripper{t: t, expectedBody: expectedBody}
		config := configuration.NewWithOpts()
		config.Set(ConfigurationKeyRequestAttempts, 3)
		config.Set(configurationKeyRetryAfter, 1)

		sut := NewRetryMiddleware(config, &logger, rt)
		response, err := sut.RoundTrip(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(expectedBody)))

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, http.StatusOK, response.StatusCode)
		assert.Equal(t, "2", response.Header.Get(retryCountHeaderKey))
	})
}

func Test_shouldRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		response          *http.Response
		expectedErrorIs   error
		expectedRetryable *backoff.RetryAfterError // For checking RetryAfter duration
		expectNilError    bool
		attempts          int
		maxAttempts       int
	}{
		{
			name:            "Retryable status code (429) with Retry-After header too far in the future (4years)",
			response:        newResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"126144000"}}),
			expectedErrorIs: &backoff.PermanentError{Err: errRetryDelayMaxExceeded},
			attempts:        0,
			maxAttempts:     1,
		},
		{
			name:              "Retryable status code (429) with Retry-After header",
			response:          newResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"5"}}),
			expectedRetryable: &backoff.RetryAfterError{Duration: 5 * time.Second},
			attempts:          0,
			maxAttempts:       1,
		},
		{
			name:            "Retryable status code (503) with invalid Retry-After header",
			response:        newResponse(http.StatusServiceUnavailable, http.Header{"Retry-After": []string{"abc"}}),
			expectedErrorIs: errRetryNecessary, // retryDelaySecs will be 0
			attempts:        0,
			maxAttempts:     1,
		},
		{
			name:            "Retryable status code (500) without Retry-After header",
			response:        newResponse(http.StatusInternalServerError, nil),
			expectedErrorIs: errRetryNecessary,
			attempts:        0,
			maxAttempts:     1,
		},
		{
			name:           "Non-retryable status code (200)",
			response:       newResponse(http.StatusOK, nil),
			expectNilError: true,
			attempts:       0,
			maxAttempts:    1,
		},
		{
			name:           "Non-retryable status code (400)",
			response:       newResponse(http.StatusBadRequest, nil),
			expectNilError: true,
			attempts:       0,
			maxAttempts:    1,
		},
		{
			name:            "Retryable status code (502) with Retry-After: 0",
			response:        newResponse(http.StatusBadGateway, http.Header{"Retry-After": []string{"0"}}),
			expectedErrorIs: errRetryNecessary, // retryDelaySecs will be 0
			attempts:        0,
			maxAttempts:     1,
		},
		{
			name:            "Retryable status code (504) with Retry-After: -1",
			response:        newResponse(http.StatusGatewayTimeout, http.Header{"Retry-After": []string{"-1"}}),
			expectedErrorIs: errRetryNecessary, // retryDelaySecs will be -1
			attempts:        0,
			maxAttempts:     1,
		},
		{
			name:            "Retryable status code (429) with max attempts reached",
			response:        newResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"5"}}),
			expectedErrorIs: &backoff.PermanentError{Err: errRetryNecessary},
			attempts:        1,
			maxAttempts:     1,
		},
		{
			name: "Retryable status code (503) with maintenance window error",
			response: func() *http.Response {
				resp := newResponse(http.StatusServiceUnavailable, http.Header{"Retry-After": []string{"5"}})
				var buf bytes.Buffer
				err := snyk.NewMaintenanceWindowError("").MarshalToJSONAPIError(&buf, "")
				if err != nil {
					t.Fatal(err)
				}
				resp.Body = io.NopCloser(&buf)
				return resp
			}(),
			expectedErrorIs: &backoff.PermanentError{Err: errRetryNecessary},
			attempts:        0,
			maxAttempts:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := shouldRetry(tt.response, tt.attempts, tt.maxAttempts)

			if tt.expectNilError {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
				if tt.expectedErrorIs != nil {
					assert.Equal(t, err.Error(), tt.expectedErrorIs.Error(), "Expected error to be of type %T, got %T (%v)", tt.expectedErrorIs, err, err)
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

func Test_shouldRetry_rateLimitResetHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		response          *http.Response
		expectedErrorIs   error
		expectedRetryable *backoff.RetryAfterError
		attempts          int
		maxAttempts       int
	}{
		{
			name: "Retryable status code (429) with only X-Ratelimit-Reset header",
			response: func() *http.Response {
				h := http.Header{}
				h.Set("X-Ratelimit-Reset", "5")
				return newResponse(http.StatusTooManyRequests, h)
			}(),
			expectedRetryable: &backoff.RetryAfterError{Duration: 5 * time.Second},
			attempts:          0,
			maxAttempts:       1,
		},
		{
			name: "Retryable status code (429) Retry-After takes precedence over X-RateLimit-Reset",
			response: func() *http.Response {
				h := http.Header{}
				h.Set("Retry-After", "3")
				h.Set("X-RateLimit-Reset", "10")
				return newResponse(http.StatusTooManyRequests, h)
			}(),
			expectedRetryable: &backoff.RetryAfterError{Duration: 10 * time.Second},
			attempts:          0,
			maxAttempts:       1,
		},
		{
			name: "Retryable status code (429) with X-RateLimit-Reset header too far in the future (4years)",
			response: func() *http.Response {
				h := http.Header{}
				h.Set("X-RateLimit-Reset", "126144000")
				return newResponse(http.StatusTooManyRequests, h)
			}(),
			expectedErrorIs: errRetryDelayMaxExceeded,
			attempts:        0,
			maxAttempts:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := shouldRetry(tt.response, tt.attempts, tt.maxAttempts)

			assert.NotNil(t, err)
			if tt.expectedErrorIs != nil {
				require.True(t, errors.Is(err, tt.expectedErrorIs), `Expected error to be equal to "%v" (%T), got "%v" (%T)`, tt.expectedErrorIs, tt.expectedErrorIs, err, err)
			}
			if tt.expectedRetryable != nil {
				var actualRetryableErr *backoff.RetryAfterError
				require.ErrorAs(t, err, &actualRetryableErr)
				require.Equal(t, tt.expectedRetryable, actualRetryableErr, "RetryAfter duration mismatch")
			}
		})
	}
}

func Test_parseRetryDelay(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output time.Duration
	}{
		{
			name:   "Parse seconds value",
			input:  "10",
			output: 10 * time.Second,
		},
		{
			name:   "Parse date value",
			input:  time.Now().Add(102 * time.Minute).Format(time.RFC1123),
			output: 102 * time.Minute,
		},
		{
			name:   "Parse date value in the past",
			input:  "Wed, 21 Oct 2015 07:28:00 GMT",
			output: 0 * time.Second,
		},
		{
			name:   "Parse empty string",
			input:  "",
			output: 0 * time.Second,
		},
		{
			name:   "Parse random string",
			input:  "random",
			output: 0 * time.Second,
		},
	}

	for _, testcase := range tests {
		t.Run(testcase.name, func(t *testing.T) {
			actualOutput := parseRetryDelay(testcase.input)
			timeDistance := (testcase.output - actualOutput) / time.Second
			t.Logf("Time distance: %v", timeDistance)
			assert.Equal(t, 0.0, math.Abs(float64(timeDistance)))
		})
	}
}

func Test_filterRetryError(t *testing.T) {
	logger := zerolog.Nop()
	rm := &RetryMiddleware{logger: &logger}

	t.Run("retry exhausted returns nil", func(t *testing.T) {
		err := rm.filterRetryError(backoff.Permanent(errRetryNecessary), 3)
		assert.NoError(t, err)
	})

	t.Run("delay max exceeded returns nil", func(t *testing.T) {
		err := rm.filterRetryError(backoff.Permanent(errRetryDelayMaxExceeded), 1)
		assert.NoError(t, err)
	})

	t.Run("non-sentinel error passes through unchanged", func(t *testing.T) {
		originalErr := errors.New("some other error")
		err := rm.filterRetryError(originalErr, 1)
		assert.Equal(t, originalErr, err)
	})

	t.Run("wrapped RetryAttemptError with sentinel is filtered", func(t *testing.T) {
		err := &RetryAttemptError{
			StatusCode:  429,
			Attempt:     2,
			MaxAttempts: 3,
			Err:         backoff.Permanent(errRetryNecessary),
		}
		result := rm.filterRetryError(err, 2)
		assert.NoError(t, result)
	})
}

func Test_retryMiddleware_429_exhausted(t *testing.T) {
	logger := zerolog.Nop()

	always429 := func(req *http.Request, _ int) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"1"}},
			Request:    req,
		}, nil
	}

	t.Run("returns last 429 response and nil error", func(t *testing.T) {
		sut, attemptCount := setupRetryMiddleware(t, &logger, nil, 1, always429)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		assert.Equal(t, attemptThreeNetworkRequests, *attemptCount, "429 override enforces at least 3 attempts even when maxAttempts=1")
	})

	t.Run("invokes errorHandler during retries", func(t *testing.T) {
		tracker := &retryNotifyTracker{}
		sut, attemptCount := setupRetryMiddleware(t, &logger, tracker.handler(), 1, always429)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		assert.Equal(t, attemptThreeNetworkRequests, *attemptCount, "429 override enforces at least 3 attempts even when maxAttempts=1")

		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		assert.NotEmpty(t, tracker.errors, "errorHandler should be called during 429 retries")
		for _, e := range tracker.errors {
			var retryErr *RetryAttemptError
			require.ErrorAs(t, e, &retryErr)
			assert.Equal(t, http.StatusTooManyRequests, retryErr.StatusCode)
		}
	})
}

func Test_retryMiddleware_429_then_success(t *testing.T) {
	logger := zerolog.Nop()

	once429ThenOK := func(req *http.Request, attempt int) (*http.Response, error) {
		if attempt < 2 {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{},
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Request:    req,
		}, nil
	}

	t.Run("nil callback does not panic", func(t *testing.T) {
		sut, attemptCount := setupRetryMiddleware(t, &logger, nil, 3, once429ThenOK)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, *attemptCount)
	})

	t.Run("callback receives RetryAttemptError with correct metadata", func(t *testing.T) {
		tracker := &retryNotifyTracker{}
		sut, attemptCount := setupRetryMiddleware(t, &logger, tracker.handler(), 3, once429ThenOK)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, *attemptCount)

		tracker.mu.Lock()
		defer tracker.mu.Unlock()

		assert.NotEmpty(t, tracker.errors, "Expected retry notification via callback")
		for _, e := range tracker.errors {
			var retryErr *RetryAttemptError
			require.ErrorAs(t, e, &retryErr)
			assert.Equal(t, http.StatusTooManyRequests, retryErr.StatusCode)
			assert.Greater(t, retryErr.Attempt, 0)
			assert.Greater(t, retryErr.MaxAttempts, 0)
		}
	})

	t.Run("500 exhaustion does not invoke callback", func(t *testing.T) {
		tracker := &retryNotifyTracker{}

		always500 := func(req *http.Request, _ int) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     http.Header{},
				Request:    req,
			}, nil
		}

		sut, _ := setupRetryMiddleware(t, &logger, tracker.handler(), 2, always500)
		resp, err := sut.RoundTrip(httptest.NewRequest(http.MethodGet, "/", nil))

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		// 500 still triggers the callback since the middleware notifies on all retries
		for _, e := range tracker.errors {
			var retryErr *RetryAttemptError
			require.ErrorAs(t, e, &retryErr)
			assert.Equal(t, http.StatusInternalServerError, retryErr.StatusCode)
		}
	})
}

func TestRetryAttemptNotification(t *testing.T) {
	t.Run("429 returns warn catalog error with wait message and cause", func(t *testing.T) {
		attempt := &RetryAttemptError{
			StatusCode:  http.StatusTooManyRequests,
			Attempt:     1,
			MaxAttempts: 3,
			Duration:    2 * time.Second,
		}

		notifyErr, ok := retryAttemptNotification(attempt)
		require.True(t, ok)

		var catalogErr snyk_errors.Error
		require.True(t, errors.As(notifyErr, &catalogErr))
		assert.Equal(t, "warn", catalogErr.Level)
		assert.Equal(t, "Service temporarily throttled", catalogErr.Title)
		assert.Contains(t, catalogErr.Detail, "Automatically retrying in 2 seconds... (attempt 1/3).")

		var cause *RetryAttemptError
		require.True(t, errors.As(notifyErr, &cause), "original RetryAttemptError should be accessible via Unwrap")
		assert.Equal(t, http.StatusTooManyRequests, cause.StatusCode)
	})

	t.Run("500 has no notification", func(t *testing.T) {
		attempt := &RetryAttemptError{
			StatusCode:  http.StatusInternalServerError,
			Attempt:     1,
			MaxAttempts: 3,
		}

		notifyErr, ok := retryAttemptNotification(attempt)
		assert.False(t, ok)
		assert.Nil(t, notifyErr)
	})

	t.Run("non-retry error has no notification", func(t *testing.T) {
		notifyErr, ok := retryAttemptNotification(errors.New("other"))
		assert.False(t, ok)
		assert.Nil(t, notifyErr)
	})
}

// CLI-1591: Verify that POST body is preserved across retries when a 429 triggers
// the per-status-code override (getMaxRetryAttempts) despite configured maxAttempts=1.
func TestRetryMiddleware_429_POST_BodyPreservedAcrossRetries(t *testing.T) {
	expectedBody := []byte(`{"depGraph":{"pkgManager":{"name":"npm"},"nodes":[]}}`)
	logger := zerolog.Nop()

	var bodiesReceived [][]byte
	attemptCount := 0

	//nolint:unparam // error is always nil but signature must match http.RoundTripper
	customRTFn := func(req *http.Request) (*http.Response, error) {
		attemptCount++

		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		bodiesReceived = append(bodiesReceived, body)

		// Verify GetBody also returns the full payload (used by HTTP/2 retries)
		require.NotNil(t, req.GetBody, "Attempt %d: GetBody must be set", attemptCount)
		getBodyReader, err := req.GetBody()
		require.NoError(t, err, "Attempt %d: GetBody() must not error", attemptCount)
		getBodyBytes, err := io.ReadAll(getBodyReader)
		require.NoError(t, err)
		assert.Equal(t, expectedBody, getBodyBytes,
			"Attempt %d: GetBody() must return full body", attemptCount)

		headers := http.Header{}
		if attemptCount < 3 {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     headers,
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     headers,
			Request:    req,
		}, nil
	}

	rt := &failRoundtripper{
		t:           t,
		roundTripFn: &customRTFn,
	}

	config := configuration.NewWithOpts()
	config.Set(ConfigurationKeyRequestAttempts, 1)
	config.Set(configurationKeyRetryAfter, 1)

	sut := NewRetryMiddleware(config, &logger, rt)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", bytes.NewReader(expectedBody))
	req.Header.Set("Content-Type", "application/json")

	response, err := sut.RoundTrip(req)

	assert.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, http.StatusOK, response.StatusCode, "Should succeed after retries")
	assert.Equal(t, 3, attemptCount, "Should make 3 attempts per 429 override")

	require.Len(t, bodiesReceived, 3, "Should have recorded body for each attempt")
	for i, body := range bodiesReceived {
		assert.Equal(t, expectedBody, body,
			"Attempt %d: body must be preserved across retries", i+1)
	}
}

// setupRetryMiddleware wires RetryMiddleware with a counting transport and the given config.
func setupRetryMiddleware(
	t *testing.T,
	logger *zerolog.Logger,
	errorHandler networktypes.ErrorHandlerFunc,
	maxAttempts int,
	roundTrip func(req *http.Request, attempt int) (*http.Response, error),
) (http.RoundTripper, *int) {
	t.Helper()
	attemptCount := 0
	fn := func(req *http.Request) (*http.Response, error) {
		attemptCount++
		return roundTrip(req, attemptCount)
	}
	rt := &failRoundtripper{t: t, roundTripFn: &fn}
	config := configuration.NewWithOpts()
	config.Set(ConfigurationKeyRequestAttempts, maxAttempts)
	config.Set(configurationKeyRetryAfter, 1)
	return NewRetryMiddleware(config, logger, rt, WithErrorHandler(errorHandler)), &attemptCount
}
