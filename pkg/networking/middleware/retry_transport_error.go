package middleware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// Windows WSAECONNRESET (10054); Go's syscall package does not map it onto
// syscall.ECONNRESET the way POSIX does, so it must be matched by numeric value.
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
	if isSafeMethod(req.Method) {
		return true
	}
	return isAllowedPath(req.URL.Path, retryAllowedPaths(config))
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// IsSet (not len>0) so an explicit empty override is honored rather than treated as unset.
func retryAllowedPaths(config configuration.Configuration) []string {
	if config.IsSet(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS) {
		return config.GetStringSlice(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS)
	}
	return constants.DEFAULT_RETRY_ALLOWED_PATHS
}

// Contiguous-segment matching avoids near-misses like /v1/test-dep-graph-something.
// A blank entry would otherwise match the empty leading segment of every absolute path.
func isAllowedPath(path string, allowed []string) bool {
	segments := strings.Split(path, "/")
	for _, entry := range allowed {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		if containsContiguous(segments, strings.Split(entry, "/")) {
			return true
		}
	}
	return false
}

func containsContiguous(segments, entry []string) bool {
	if len(entry) == 0 || len(entry) > len(segments) {
		return false
	}
	for start := 0; start+len(entry) <= len(segments); start++ {
		match := true
		for i, part := range entry {
			if segments[start+i] != part {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
