package middleware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// defaultRetryExcludedPathSegments mirrors today's monitor-only exclusion,
// used when the consumer has not configured NETWORK_REQUEST_RETRY_EXCLUDED_PATH_SEGMENTS.
var defaultRetryExcludedPathSegments = []string{"monitor"}

// errWSAEConnReset is the Windows WSAECONNRESET error code (10054). Go's
// syscall package does not map it onto syscall.ECONNRESET the way POSIX
// does, so it must be matched explicitly by numeric value.
const errWSAEConnReset = syscall.Errno(10054)

func isConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, errWSAEConnReset)
}

// context.DeadlineExceeded also satisfies net.Error.Timeout(), so the
// cancellation/deadline deny-check must run before the timeout allow-check.
func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if isConnectionReset(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isRetryableRequest(req *http.Request, config configuration.Configuration) bool {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false
	}
	return !isExcludedPath(req.URL.Path, retryExcludedPathSegments(config))
}

// retryExcludedPathSegments returns the configured deny-list, falling back to
// defaultRetryExcludedPathSegments when unset.
func retryExcludedPathSegments(config configuration.Configuration) []string {
	if segments := config.GetStringSlice(configuration.NETWORK_REQUEST_RETRY_EXCLUDED_PATH_SEGMENTS); len(segments) > 0 {
		return segments
	}
	return defaultRetryExcludedPathSegments
}

// isExcludedPath excludes endpoints whose side effects make a retried
// duplicate unsafe (e.g. monitor, which creates a snapshot resource).
func isExcludedPath(path string, denySegments []string) bool {
	for _, segment := range strings.Split(path, "/") {
		for _, denied := range denySegments {
			if segment == denied {
				return true
			}
		}
	}
	return false
}
