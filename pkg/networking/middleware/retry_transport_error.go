package middleware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// context.DeadlineExceeded also satisfies net.Error.Timeout(), so the
// cancellation/deadline deny-check must run before the timeout allow-check.
func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if isConnectionResetError(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isRetryableRequest(req *http.Request, config configuration.Configuration) bool {
	if isSafeMethod(req.Method) {
		return true
	}
	return isAllowedPath(req.URL.Path, config.GetStringSlice(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS))
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// Contiguous-segment matching avoids near-misses: an entry "foo" must not match /v1/foo-something.
// A blank entry would otherwise match the empty leading segment of every absolute path.
// Entries are normalized: leading and trailing slashes are trimmed, and whitespace is stripped.
func isAllowedPath(path string, allowed []string) bool {
	for _, entry := range allowed {
		// Trim whitespace and leading/trailing slashes from the entry.
		trimmed := strings.Trim(strings.TrimSpace(entry), "/")
		if trimmed == "" {
			continue
		}
		// Slash-padded containment check: "/"+path+"/" contains "/"+trimmed+"/".
		// This ensures contiguous-segment matching without near-misses.
		if strings.Contains("/"+path+"/", "/"+trimmed+"/") {
			return true
		}
	}
	return false
}
