package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const defaultRetryCount uint = 1 // Per default retries (=1) are disabled and need to be enabled via the configuration
const defaultRetryAfterSeconds = 5
const maxRetryAfter = 10 * time.Minute
const ConfigurationKeyRetryAttempts = "internal_network_request_max_attempts"
const configurationKeyRetryAfter = "internal_network_request_retry_after_seconds"
const retryCountHeaderKey = "Snyk-Request-Attempt-Count"

type RetryLogic struct {
	shouldRetry      bool
	maxRetryOverride *uint
}

var attemptThreeNetworkRequests uint = 3

// This lookup table defines the response status codes that should be retried and the ability to override the default retry count
var statusCodesToRetryLUT = map[int]RetryLogic{
	http.StatusTooManyRequests:     {true, &attemptThreeNetworkRequests},
	http.StatusTooEarly:            {true, nil},
	http.StatusRequestTimeout:      {true, nil},
	http.StatusInternalServerError: {true, nil},
	http.StatusBadGateway:          {true, nil},
	http.StatusServiceUnavailable:  {true, nil},
	http.StatusGatewayTimeout:      {true, nil},
}

var errRetryNecessary = errors.New("retry with backoff")
var errRetryAfterHeaderError = errors.New("retry-after is too much in the future")

type RetryMiddleware struct {
	nextRoundtripper http.RoundTripper
	config           configuration.Configuration
	logger           *zerolog.Logger
}

func NewRetryMiddleware(config configuration.Configuration, logger *zerolog.Logger, roundTripper http.RoundTripper) *RetryMiddleware {
	return &RetryMiddleware{
		nextRoundtripper: roundTripper,
		config:           config,
		logger:           logger,
	}
}

func (rm RetryMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	var finalResponse *http.Response
	var finalError error
	var localBodyBuffer []byte
	var maxAttempts = defaultRetryCount
	var retryAfterSeconds = defaultRetryAfterSeconds
	var actualAttempts uint = 0
	var cachedMaxRetries *uint = nil // Per-request cached max retries

	if tmp := (uint)(rm.config.GetInt(ConfigurationKeyRetryAttempts)); tmp > 0 {
		maxAttempts = tmp
	}

	if tmp := rm.config.GetInt(configurationKeyRetryAfter); tmp > 0 {
		retryAfterSeconds = tmp
	}

	// if a body is available, create a local copy to be able to use it multiple times
	if req.Body != nil && maxAttempts > 1 {
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
	}

	op := func() (*http.Response, error) {
		actualAttempts++

		// create a local copy of the request
		localRequest := *req
		if len(localBodyBuffer) > 0 {
			localRequest.Body = io.NopCloser(bytes.NewBuffer(localBodyBuffer))
		}

		// try to send request
		response, err := rm.nextRoundtripper.RoundTrip(&localRequest)

		// keep track of actual retry attempts for monitoring/logging
		if response != nil && response.Header != nil && actualAttempts > 1 {
			response.Header.Set(retryCountHeaderKey, fmt.Sprintf("%d", actualAttempts))
		}

		// errors from the next round tripper cannot not be retried
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
			return response, retryError
		}

		return response, nil
	}

	backoffMethod := backoff.NewExponentialBackOff()
	backoffMethod.InitialInterval = time.Duration(retryAfterSeconds) * time.Second
	finalResponse, finalError = backoff.Retry(req.Context(), op, backoff.WithBackOff(backoffMethod))

	// if retries fail to resolve the issue, we need to unset the locally used error type to not return it from the RoundTripper
	if errors.Is(finalError, errRetryNecessary) {
		rm.logger.Warn().Msgf("Retry ultimately failed after %d attempts", actualAttempts)
		finalError = nil
	}

	return finalResponse, finalError
}

func getMaxRetryAttempts(response *http.Response, maxAttempts uint) uint {
	attempts := statusCodesToRetryLUT[response.StatusCode].maxRetryOverride
	if attempts != nil {
		return max(*attempts, maxAttempts)
	}
	return maxAttempts
}

func shouldRetry(response *http.Response, attempts uint, maxAttempts uint) error {
	if statusCodesToRetryLUT[response.StatusCode].shouldRetry {
		// if we have reached the maximum number of permitted attempts, stop retrying
		if attempts >= maxAttempts {
			// return backoff.Permanent() to end the retry loop
			return backoff.Permanent(errRetryNecessary)
		}

		fixRetryDelay := time.Duration(0)

		// try to read retry-after header if available
		if headerRetryAfterValue := response.Header.Get("Retry-After"); len(headerRetryAfterValue) > 0 {
			fixRetryDelay = parseRetryAfterHeader(headerRetryAfterValue)
		}

		// if the fix retry delay is too big, we rather fail permanently than blocking too long
		if fixRetryDelay > maxRetryAfter {
			return backoff.Permanent(errRetryAfterHeaderError)
		}

		// if a retry after is defined, this is the time to wait for
		if fixRetryDelay > 0 {
			return &backoff.RetryAfterError{Duration: fixRetryDelay}
		}

		// if no retry after is defined, the backoff strategy determines the time to wait for
		return errRetryNecessary
	}

	return nil
}

func parseRetryAfterHeader(headerRetryAfterValue string) time.Duration {
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
