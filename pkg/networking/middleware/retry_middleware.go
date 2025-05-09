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
const ConfigurationKeyRetryCount = "internal_network_request_max_attempts"
const configurationKeyRetryAfter = "internal_network_request_retry_after_seconds"
const retryCountHeaderKey = "Snyk-Request-Attempt-Count"

var statusCodesToRetryLUT = map[int]bool{
	http.StatusTooManyRequests:     true,
	http.StatusTooEarly:            true,
	http.StatusRequestTimeout:      true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

var errRetryNecessary = errors.New("retry error")

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
	var actualAttempts = 0

	if tmp := (uint)(rm.config.GetInt(ConfigurationKeyRetryCount)); tmp > 0 {
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

		// depending on the response determine if we should retry
		if retryError := shouldRetry(response, retryAfterSeconds); retryError != nil {
			rm.logger.Debug().Msgf("Retrying request, reason: %v", retryError)
			return response, retryError
		}

		return response, nil
	}

	backoffMethod := backoff.NewExponentialBackOff()
	backoffMethod.InitialInterval = time.Duration(retryAfterSeconds) * time.Second
	finalResponse, finalError = backoff.Retry(req.Context(), op, backoff.WithBackOff(backoffMethod), backoff.WithMaxTries(maxAttempts))

	// if retries fail to resolve the issue, we need to unset the locally used error type to not return it from the RoundTripper
	if errors.Is(finalError, errRetryNecessary) {
		finalError = nil
	}

	return finalResponse, finalError
}

func shouldRetry(response *http.Response, defaultRetryDelay int) error {
	var retryError error

	if statusCodesToRetryLUT[response.StatusCode] {
		retryDelaySecs := 0

		// try to read retry-after header if available
		if headerRetryAfterValue := response.Header.Get("Retry-After"); len(headerRetryAfterValue) > 0 {
			tmp, err := strconv.ParseInt(headerRetryAfterValue, 10, 64)
			if err == nil {
				retryDelaySecs = int(tmp)
			} else {
				retryDelaySecs = defaultRetryDelay
			}
		}

		if retryDelaySecs > 0 {
			retryError = backoff.RetryAfter(retryDelaySecs)
		} else {
			retryError = errRetryNecessary
		}
	}

	return retryError
}
