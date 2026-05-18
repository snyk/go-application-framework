package middleware

import (
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

func (rm RetryMiddleware) shouldShowRateLimitWarning(lastStatusCode int) bool {
	return rm.ui != nil && lastStatusCode == http.StatusTooManyRequests
}

func (rm RetryMiddleware) rateLimitNotifyFunc(
	lastStatusCode *int,
	actualAttempts *int,
	cachedMaxRetries **int,
	maxAttempts int,
) func(error, time.Duration) {
	return func(_ error, duration time.Duration) {
		if !rm.shouldShowRateLimitWarning(*lastStatusCode) {
			return
		}
		resolvedMax := maxAttempts
		if *cachedMaxRetries != nil {
			resolvedMax = **cachedMaxRetries
		}
		rm.showRateLimitWaitWarning(duration, *actualAttempts, resolvedMax)
	}
}

func (rm RetryMiddleware) showRateLimitWaitWarning(duration time.Duration, attempt int, maxAttempts int) {
	if rm.ui == nil {
		return
	}

	totalSecs := int(math.Ceil(duration.Seconds()))
	if totalSecs <= 0 {
		totalSecs = 1
	}

	waitErr := snyk_errors.Error{
		Title:       "Rate limited",
		Description: fmt.Sprintf("Waiting up to %ds before retry (attempt %d/%d).", totalSecs, attempt, maxAttempts),
		Level:       "warn",
	}
	if err := rm.ui.OutputError(waitErr); err != nil {
		rm.logger.Debug().Err(err).Msg("failed to show rate-limit wait warning")
	}
}
