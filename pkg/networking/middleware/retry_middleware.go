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
	"strings"
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

		rawDelay := rateLimitRetryDelay(response)
		if rawDelay > maxRetryAfter {
			return backoff.Permanent(errRetryDelayMaxExceeded)
		}

		// Wait the full suggested delay (Retry-After or X-RateLimit-Reset,
		// whichever is longer), then add random extra in [0, jitter window) to
		// desynchronize concurrent clients. Both headers get the same
		// treatment — there's no reason to trust one as more "exact" than the
		// other, and a single unconditional branch keeps this simple. The
		// jitter window scales with the bucket's actual capacity (see
		// rateLimitJitterWindow) instead of a flat constant, so low-capacity
		// buckets get more spread.
		var timeToWait time.Duration
		if rawDelay > 0 {
			timeToWait = rawDelay + time.Duration(rand.N(int64(rateLimitJitterWindow(response, rawDelay))))
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

// rateLimitRetryDelay extracts the longer of Retry-After and X-RateLimit-Reset
// durations from the response headers. The returned value is the raw header
// value — suitable for error reporting ("retry after N seconds") but not for
// the actual sleep, which applies jitter separately (see rateLimitJitterWindow).
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

// maxJitterWindow is the extra random delay added on top of the raw retry
// delay (Retry-After or X-RateLimit-Reset). All clients wait at least that
// long (guaranteeing the bucket has refilled), then each adds a random extra
// in [0, maxJitterWindow) to desynchronize their retries.
const maxJitterWindow = 2 * time.Second

// referenceRate is a portable, round req/s threshold, not an assumed client
// count: routes at/above it keep today's flat maxJitterWindow; below it,
// jitter widens proportionally. This is a heuristic that reduces re-throttle
// odds for tight-capacity routes — it cannot guarantee zero collisions,
// since GAF has no visibility into how many other clients are retrying the
// same route concurrently.
const referenceRate = 100.0 // req/s
const jitterCeiling = 60 * time.Second

type rateLimitPolicy struct {
	limit         int
	windowSeconds int
}

// parseRateLimitPolicies parses the IETF RateLimit-Limit draft format, e.g.
// `160, 160;w=1;name="...", 1620;w=60;name="...", 97200;w=3600;name="..."`.
// The bare leading value (no `w=`) has no window attached and is skipped —
// its unit can't be determined without one.
func parseRateLimitPolicies(header string) []rateLimitPolicy {
	var policies []rateLimitPolicy
	for _, entry := range strings.Split(header, ",") {
		parts := strings.Split(entry, ";")
		limit, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || limit <= 0 {
			continue
		}
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			if w, ok := strings.CutPrefix(p, "w="); ok {
				if window, err := strconv.Atoi(w); err == nil && window > 0 {
					policies = append(policies, rateLimitPolicy{limit, window})
				}
			}
		}
	}
	return policies
}

// rateLimitJitterWindow sizes the extra random delay added on top of a raw
// retry delay wait. It matches X-RateLimit-Limit's policy list against
// rawDelay (the countdown already being waited on) to find the actual
// bucket capacity, then scales the jitter window inversely with that
// capacity: low-capacity buckets get more spread, high-capacity buckets keep
// today's flat maxJitterWindow. Falls back to maxJitterWindow whenever the
// header is missing, unparseable, or no policy's window covers rawDelay.
func rateLimitJitterWindow(res *http.Response, rawDelay time.Duration) time.Duration {
	var matched *rateLimitPolicy
	for _, p := range parseRateLimitPolicies(res.Header.Get("X-RateLimit-Limit")) {
		windowDur := time.Duration(p.windowSeconds) * time.Second
		if windowDur >= rawDelay && (matched == nil || p.windowSeconds < matched.windowSeconds) {
			policy := p
			matched = &policy
		}
	}
	if matched == nil {
		return maxJitterWindow
	}

	rate := float64(matched.limit) / float64(matched.windowSeconds)
	window := time.Duration(float64(maxJitterWindow) * (referenceRate / rate))
	if window < maxJitterWindow {
		window = maxJitterWindow
	}
	if window > jitterCeiling {
		window = jitterCeiling
	}
	return window
}
