package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

const defaultMaxAttemptsCount = 1 // Per default max network attempts (=1) this means retries are disabled and need to be enabled via the configuration
const defaultRetryAfterSeconds = 5
const maxRetryAfter = 10 * time.Minute
const ConfigurationKeyRequestAttempts = "internal_network_request_max_attempts"
const configurationKeyRetryAfter = "internal_network_request_retry_after_seconds"
const retryCountHeaderKey = "Snyk-Request-Attempt-Count"

type retryLogic struct {
	shouldRetry      bool
	maxRetryOverride *int
}

var attemptThreeNetworkRequests int = 3

// This lookup table defines the response status codes that should be retried and the ability to override the default retry count
var statusCodesToRetryLUT = map[int]retryLogic{
	http.StatusTooManyRequests:     {true, &attemptThreeNetworkRequests},
	http.StatusTooEarly:            {true, nil},
	http.StatusRequestTimeout:      {true, nil},
	http.StatusInternalServerError: {true, nil},
	http.StatusBadGateway:          {true, nil},
	http.StatusServiceUnavailable:  {true, nil},
	http.StatusGatewayTimeout:      {true, nil},
}

var errRetryNecessary = errors.New("retry with backoff")
var errRetryDelayMaxExceeded = errors.New("suggested retry delay exceeds maximum allowed wait")

type RetryAttemptError struct {
	StatusCode  int
	Attempt     int
	MaxAttempts int
	Duration    time.Duration
	Err         error
}

func (e *RetryAttemptError) Error() string {
	return fmt.Sprintf("retry attempt %d/%d (status %d): %v", e.Attempt, e.MaxAttempts, e.StatusCode, e.Err)
}

func (e *RetryAttemptError) Unwrap() error {
	return e.Err
}

type RetryMiddleware struct {
	nextRoundtripper http.RoundTripper
	config           configuration.Configuration
	logger           *zerolog.Logger
	errorHandler     networktypes.ErrorHandlerFunc
}

type RetryMiddlewareOption func(*RetryMiddleware)

func WithErrorHandler(handler networktypes.ErrorHandlerFunc) RetryMiddlewareOption {
	return func(rm *RetryMiddleware) {
		rm.errorHandler = handler
	}
}

func NewRetryMiddleware(config configuration.Configuration, logger *zerolog.Logger, roundTripper http.RoundTripper, opts ...RetryMiddlewareOption) *RetryMiddleware {
	rm := &RetryMiddleware{
		nextRoundtripper: roundTripper,
		config:           config,
		logger:           logger,
	}
	for _, opt := range opts {
		opt(rm)
	}
	return rm
}

func (rm RetryMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	var finalResponse *http.Response
	var finalError error
	var localBodyBuffer []byte
	var maxAttempts = defaultMaxAttemptsCount
	var retryAfterSeconds = defaultRetryAfterSeconds
	var actualAttempts int = 0
	var cachedMaxRetries *int = nil // Per-request cached max retries

	if tmp := rm.config.GetInt(ConfigurationKeyRequestAttempts); tmp > 0 {
		maxAttempts = tmp
	}

	if tmp := rm.config.GetInt(configurationKeyRetryAfter); tmp > 0 {
		retryAfterSeconds = tmp
	}

	// if a body is available, create a local copy to be able to use it multiple times.
	// Always buffer: per-status-code overrides (e.g. 429 → 3 attempts) can trigger retries
	// regardless of the configured maxAttempts, so the body must be available for reuse.
	if req.Body != nil && req.Body != http.NoBody {
		// possible optimization for large request bodies to not buffer in memory but in filesystem
		var localBufferError error
		localBodyBuffer, localBufferError = io.ReadAll(req.Body)
		closeError := req.Body.Close()

		if localBufferError != nil {
			return nil, localBufferError
		}
		if closeError != nil {
			return nil, closeError
		}

		req.Body = io.NopCloser(bytes.NewBuffer(localBodyBuffer))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewBuffer(localBodyBuffer)), nil
		}
	}

	op := func() (*http.Response, error) {
		actualAttempts++

		// create a local copy of the request
		localRequest := *req
		if len(localBodyBuffer) > 0 {
			localRequest.Body = io.NopCloser(bytes.NewBuffer(localBodyBuffer))
			localRequest.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewBuffer(localBodyBuffer)), nil
			}
		}

		// try to send request
		response, err := rm.nextRoundtripper.RoundTrip(&localRequest)

		// keep track of actual retry attempts for monitoring/logging
		if response != nil && response.Header != nil && actualAttempts > 1 {
			response.Header.Set(retryCountHeaderKey, fmt.Sprintf("%d", actualAttempts))
		}

		// errors from the next round tripper cannot be retried
		if err != nil {
			return response, backoff.Permanent(err)
		}

		// Cache max retry attempts for the current request
		if cachedMaxRetries == nil {
			calculated := getMaxRetryAttempts(response, maxAttempts)
			cachedMaxRetries = &calculated
		}

		// depending on the response determine if we should retry
		if retryError := shouldRetry(response, actualAttempts, *cachedMaxRetries); retryError != nil {
			rm.logger.Debug().Msgf("Retrying request, reason: %v", retryError)
			return response, &RetryAttemptError{
				StatusCode:  response.StatusCode,
				Attempt:     actualAttempts,
				MaxAttempts: *cachedMaxRetries,
				Err:         retryError,
			}
		}

		return response, nil
	}

	backoffMethod := backoff.NewExponentialBackOff()
	backoffMethod.InitialInterval = time.Duration(retryAfterSeconds) * time.Second
	reqCtx := req.Context()
	finalResponse, finalError = backoff.Retry(reqCtx, op,
		backoff.WithBackOff(backoffMethod),
		backoff.WithNotify(func(err error, duration time.Duration) {
			rm.notifyRetry(reqCtx, err, duration)
		}),
	)

	finalError = rm.filterRetryError(finalError, actualAttempts)
	return finalResponse, finalError
}

func (rm RetryMiddleware) notifyRetry(ctx context.Context, err error, duration time.Duration) {
	if rm.errorHandler == nil {
		return
	}
	var retryErr *RetryAttemptError
	if errors.As(err, &retryErr) {
		retryErr.Duration = duration
		if catalogErr, ok := retryAttemptNotification(retryErr); ok {
			if handlerErr := rm.errorHandler(catalogErr, ctx); handlerErr != nil {
				rm.logger.Debug().Err(handlerErr).Msg("error handler failed during retry notification")
			}
		}
	}
}

// filterRetryError hides implementation-only errors that mean “we stopped retrying
// but the last HTTP response is still valid.”
//
// After backoff.Retry, err may be errRetryNecessary (retries exhausted or a 503
// maintenance body that must not be retried) or errRetryDelayMaxExceeded
// (Retry-After / X-RateLimit-Reset would exceed our max wait). We log those and
// return nil so callers see no error alongside the last *http.Response. All other
// errors are returned unchanged.
func (rm RetryMiddleware) filterRetryError(err error, actualAttempts int) error {
	if errors.Is(err, errRetryNecessary) {
		rm.logger.Warn().Msgf("Retry ultimately failed after %d attempts", actualAttempts)
		return nil
	}
	if errors.Is(err, errRetryDelayMaxExceeded) {
		rm.logger.Warn().Msg("Suggested retry delay from Retry-After or X-RateLimit-Reset exceeds maximum allowed wait; returning last HTTP response")
		return nil
	}
	return err
}

func getMaxRetryAttempts(response *http.Response, maxAttempts int) int {
	attempts := statusCodesToRetryLUT[response.StatusCode].maxRetryOverride
	if attempts != nil {
		return max(*attempts, maxAttempts)
	}
	return maxAttempts
}

func shouldRetry(response *http.Response, attempts int, maxAttempts int) error {
	// if the Snyk API is in maintenance mode, we should not retry
	if response.StatusCode == http.StatusServiceUnavailable {
		errorList := getErrorList(response)
		for _, actualError := range errorList {
			if actualError.ErrorCode == snyk.NewMaintenanceWindowError("").ErrorCode {
				return backoff.Permanent(errRetryNecessary)
			}
		}
	}

	if statusCodesToRetryLUT[response.StatusCode].shouldRetry {
		// if we have reached the maximum number of permitted attempts, stop retrying
		if attempts >= maxAttempts {
			// return backoff.Permanent() to end the retry loop
			return backoff.Permanent(errRetryNecessary)
		}

		fixRetryDelay := time.Duration(0)

		// try to read retry-after header if available
		if headerRetryAfterValue := response.Header.Get("Retry-After"); len(headerRetryAfterValue) > 0 {
			fixRetryDelay = parseRetryDelay(headerRetryAfterValue)
		}

		fixXRateLimitReset := time.Duration(0)

		// try to read X-RateLimit-Reset header if available
		// according to envoy docs: number of seconds until reset of the current time-window
		if headerXRateLimitResetValue := response.Header.Get("X-RateLimit-Reset"); len(headerXRateLimitResetValue) > 0 {
			fixXRateLimitReset = parseRetryDelay(headerXRateLimitResetValue)
		}

		timeToWait := max(fixRetryDelay, fixXRateLimitReset)
		if timeToWait > maxRetryAfter {
			return backoff.Permanent(errRetryDelayMaxExceeded)
		}

		// if a retry after is defined, this is the time to wait for
		if timeToWait > 0 {
			return &backoff.RetryAfterError{Duration: timeToWait}
		}

		// if no retry after is defined, the backoff strategy determines the time to wait for
		return errRetryNecessary
	}

	return nil
}

func retryAttemptNotification(err error) (error, bool) {
	var attempt *RetryAttemptError
	if !errors.As(err, &attempt) || attempt.StatusCode != http.StatusTooManyRequests {
		return nil, false
	}

	totalSecs := int(math.Ceil(attempt.Duration.Seconds()))
	if totalSecs <= 0 {
		totalSecs = 1
	}

	notifMsg := fmt.Sprintf("Automatically retrying in %d seconds... (attempt %d/%d).", totalSecs, attempt.Attempt, attempt.MaxAttempts)
	notif := snyk.NewTooManyRequestsError(notifMsg, snyk_errors.WithCause(attempt))
	notif.Description = ""

	return notif, true
}

func parseRetryDelay(headerRetryAfterValue string) time.Duration {
	// Retry-After: 1230
	if tmp, err := strconv.ParseInt(headerRetryAfterValue, 10, 64); err == nil {
		return time.Duration(tmp) * time.Second
	}

	// Retry-After: Fri, 31 Dec 1999 23:59:59 GMT
	if tmp, err := time.Parse(time.RFC1123, headerRetryAfterValue); err == nil {
		if until := time.Until(tmp); until > 0 {
			return until
		}
	}

	return 0
}
