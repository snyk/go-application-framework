package middleware

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
)

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

// isReplayableRequest mirrors net/http.Transport's own isReplayable.
func isReplayableRequest(req *http.Request) bool {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return false
	}
	switch req.Method {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	if _, ok := req.Header["Idempotency-Key"]; ok {
		return true
	}
	_, ok := req.Header["X-Idempotency-Key"]
	return ok
}
