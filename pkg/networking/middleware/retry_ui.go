package middleware

import (
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

func (rm RetryMiddleware) notifyRateLimit(duration time.Duration, statusCode int, attempt int, resolvedMax int) {
	if rm.ui == nil || statusCode != http.StatusTooManyRequests {
		return
	}
	rm.showRateLimitWaitWarning(duration, attempt, resolvedMax)
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
