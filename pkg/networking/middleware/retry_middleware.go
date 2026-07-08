package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
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

// noCloseSeekBody wraps an io.ReadSeeker so that Close is suppressed during
// retries.  The underlying stream stays open and is rewound with Seek(0)
// instead of being copied into memory.  Call RealClose after the retry loop.
type noCloseSeekBody struct {
	io.ReadSeeker
	realCloser io.Closer
}

func (b *noCloseSeekBody) Close() error { return nil }
func (b *noCloseSeekBody) RealClose() error {
	if b.realCloser != nil {
		return b.realCloser.Close()
	}
	return nil
}

// drainAndClose fully reads any remaining bytes from the body and then closes
// it, enabling the underlying TCP connection to be reused by the transport.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body) //nolint:errcheck // best-effort drain for connection reuse
	_ = body.Close()
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

func (rm RetryMiddleware) RoundTrip(req *http.Request) (*http.Response, error) { //nolint:gocyclo // complexity from sequential retry logic with per-status-code overrides
	var finalResponse *http.Response
	var finalError error
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

	body, getBody, cleanup, err := ensureGetBodyExists(req)
	if err != nil {
		return nil, err
	}
	req.Body = body
	if getBody != nil {
		req.GetBody = getBody
	}
	defer func() {
		if cleanup != nil {
			_ = cleanup() //nolint:errcheck // best-effort cleanup, nothing to do on error
		}
	}()

	op := func() (*http.Response, error) {
		actualAttempts++

		// create a local copy of the request
		localRequest := *req

		// on retries, obtain a fresh body; the first attempt uses the
		// original req.Body carried over by the shallow copy above
		if actualAttempts > 1 && req.GetBody != nil {
			freshBody, getBodyErr := req.GetBody()
			if getBodyErr != nil {
				return nil, backoff.Permanent(getBodyErr)
			}
			if freshBody == nil {
				return nil, backoff.Permanent(fmt.Errorf("GetBody returned nil reader"))
			}
			localRequest.Body = freshBody
		}

		// try to send request
		response, rtErr := rm.nextRoundtripper.RoundTrip(&localRequest)

		// keep track of actual retry attempts for monitoring/logging
		if response != nil && response.Header != nil && actualAttempts > 1 {
			response.Header.Set(retryCountHeaderKey, fmt.Sprintf("%d", actualAttempts))
		}

		// errors from the next round tripper cannot be retried
		if rtErr != nil {
			return response, backoff.Permanent(rtErr)
		}

		// Cache max retry attempts for the current request
		if cachedMaxRetries == nil {
			calculated := getMaxRetryAttempts(response, maxAttempts)
			cachedMaxRetries = &calculated
		}

		// depending on the response determine if we should retry
		if retryError := shouldRetry(response, actualAttempts, *cachedMaxRetries); retryError != nil {
			rm.logger.Debug().Msgf("Retrying request, reason: %v", retryError)

			// When doing a retry, we need to drain and close the RESPONSE body, to ensure that the resources are freed
			var permErr *backoff.PermanentError
			if !errors.As(retryError, &permErr) {
				drainAndClose(response.Body)
			}

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

// ensureGetBodyExists inspects the request body and returns:
//   - body:    replacement Body for the first attempt (may be the original)
//   - getBody: function that produces a fresh reader on retries (may be nil)
//   - cleanup: called after the retry loop to release resources (may be nil)
//
// The caller is expected to assign body/getBody onto the request.
//
// Three strategies, in order of preference:
//  1. GetBody already set (e.g. http.NewRequest with *bytes.Reader) → return as-is.
//  2. Body implements io.ReadSeeker → wrap to suppress Close, Seek(0) to rewind.
//  3. Fallback: io.ReadAll into memory buffer.
func ensureGetBodyExists(req *http.Request) (io.ReadCloser, func() (io.ReadCloser, error), func() error, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req.Body, nil, nil, nil
	}

	if req.GetBody != nil {
		return req.Body, req.GetBody, nil, nil
	}

	// body can be rewound
	if rs, ok := req.Body.(io.ReadSeeker); ok {
		body := &noCloseSeekBody{ReadSeeker: rs, realCloser: req.Body}
		getBody := func() (io.ReadCloser, error) {
			if _, seekErr := rs.Seek(0, io.SeekStart); seekErr != nil {
				return nil, seekErr
			}
			return body, nil
		}
		return body, getBody, body.RealClose, nil
	}

	bodyBytes, readErr := io.ReadAll(req.Body)
	closeErr := req.Body.Close()
	if readErr != nil {
		return nil, nil, nil, readErr
	}
	if closeErr != nil {
		return nil, nil, nil, closeErr
	}

	newGetBody := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBuffer(bodyBytes)), nil
	}
	firstBody, firstBodyErr := newGetBody()
	return firstBody, newGetBody, nil, firstBodyErr
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

		// Cap check must use the raw header value, not the jittered one.
		// Jitter applied before the cap could allow a huge reset (e.g. 4 years)
		// to slip through when rand lands below maxRetryAfter.
		if rawDelay := rateLimitRetryDelay(response); rawDelay > maxRetryAfter {
			return backoff.Permanent(errRetryDelayMaxExceeded)
		}

		timeToWait := rateLimitRetryDelayJittered(response)

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

// rateLimitRetryDelay extracts the longer of Retry-After and X-RateLimit-Reset
// durations from the response headers. The returned value is the raw header
// value — suitable for error reporting ("retry after N seconds") but not for
// the actual sleep, which should use rateLimitRetryDelayJittered.
func rateLimitRetryDelay(res *http.Response) time.Duration {
	var retryAfter, rateLimitReset time.Duration

	if v := res.Header.Get("Retry-After"); len(v) > 0 {
		retryAfter = parseRetryDelay(v)
	}
	if v := res.Header.Get("X-RateLimit-Reset"); len(v) > 0 {
		rateLimitReset = parseRetryDelay(v)
	}

	return max(retryAfter, rateLimitReset)
}

// maxJitterWindow is the extra random delay added on top of the reset window.
// All clients wait at least the reset duration (guaranteeing the bucket has
// refilled), then each adds a random extra in [0, maxJitterWindow) to
// desynchronize their retries.
const maxJitterWindow = 2 * time.Second

// rateLimitRetryDelayJittered returns the actual duration to sleep before retrying
// a rate-limited request.
//
// Retry-After is respected exactly — RFC 7231 semantics require clients to wait
// at least the specified duration, so no jitter is applied.
//
// X-RateLimit-Reset (Envoy/Gloo token-bucket) carries the seconds until the
// current window resets. All clients that received the same 429 share the same
// reset value, so retrying at exactly reset causes a synchronized spike.
// The fix: every client waits the full reset (bucket guaranteed refilled) then
// adds a random extra delay in [0, maxJitterWindow). This desynchronizes retries
// without risking a retry before the bucket has actually recovered.
func rateLimitRetryDelayJittered(res *http.Response) time.Duration {
	if v := res.Header.Get("Retry-After"); len(v) > 0 {
		if d := parseRetryDelay(v); d > 0 {
			return d
		}
	}
	if v := res.Header.Get("X-RateLimit-Reset"); len(v) > 0 {
		if d := parseRetryDelay(v); d > 0 {
			// Wait the full reset window (bucket refills), then add jitter so
			// concurrent clients don't all retry at the same instant.
			return d + time.Duration(rand.N(int64(maxJitterWindow)))
		}
	}
	return 0
}
