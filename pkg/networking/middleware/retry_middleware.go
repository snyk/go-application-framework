package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

const defaultRetryCount uint = 3
const configurationKeyRetryCount = "INTERNAL_MAX_NET_RETRIES"
const defaultRetryAfterSeconds = 5

type RetryMiddleware struct {
	next   http.RoundTripper
	config configuration.Configuration
}

func NewRetryMiddleware(roundTriper http.RoundTripper, config configuration.Configuration) *RetryMiddleware {
	return &RetryMiddleware{
		next:   roundTriper,
		config: config,
	}
}

func (rm RetryMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	var finalResponse *http.Response = nil
	var finalError error = nil
	var localBodyBuffer []byte
	var maxRetryCount = defaultRetryCount

	// if a body is available, create a local copy to be able to use it multiple times
	if req.Body != nil {
		// possible optimization for large request bodies to not buffer in memory but in filesystem
		var localBufferError error
		localBodyBuffer, localBufferError = io.ReadAll(req.Body)
		if localBufferError != nil {
			return nil, localBufferError
		}
		req.Body = io.NopCloser(bytes.NewBuffer(localBodyBuffer))
	}

	if rm.config.IsSet(configurationKeyRetryCount) {
		maxRetryCount = (uint)(rm.config.GetInt(configurationKeyRetryCount))
	}

	op := func() (*http.Response, error) {
		// create a local copy of the request
		localRequest := *req
		if len(localBodyBuffer) > 0 {
			localRequest.Body = io.NopCloser(bytes.NewBuffer(localBodyBuffer))
		}

		// try to send request
		response, err := rm.next.RoundTrip(&localRequest)
		if err != nil {
			return nil, err
		}

		if retryAfterError := shouldRetry(response); retryAfterError != nil {
			return nil, retryAfterError
		}

		// depending on the response determine if we should retry
		return response, nil
	}

	backoffMethod := backoff.NewExponentialBackOff()
	backoffMethod.InitialInterval = defaultRetryAfterSeconds * time.Second
	finalResponse, finalError = backoff.Retry(req.Context(), op, backoff.WithBackOff(backoffMethod), backoff.WithMaxTries(maxRetryCount))

	return finalResponse, finalError
}

func shouldRetry(response *http.Response) error {
	var retryError error

	if response.StatusCode >= http.StatusInternalServerError ||
		response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode == http.StatusMovedPermanently {

		retryAfterSeconds := 0

		// try to read retry-after header if available
		if headerRetryAfterValue := response.Header.Get("Retry-After"); len(headerRetryAfterValue) > 0 {
			tmp, err := strconv.ParseInt(headerRetryAfterValue, 10, 64)
			if err == nil {
				retryAfterSeconds = int(tmp)
			} else {
				retryAfterSeconds = defaultRetryAfterSeconds
			}
		}

		if retryAfterSeconds > 0 {
			retryError = backoff.RetryAfter(retryAfterSeconds)
		} else {
			retryError = errors.New(response.Status)
		}
	}

	return retryError
}
