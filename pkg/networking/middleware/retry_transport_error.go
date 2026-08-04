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

// isConnectionReset reports whether err is (or wraps) a TCP connection reset,
// on POSIX (syscall.ECONNRESET) or Windows (WSAECONNRESET).
func isConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, errWSAEConnReset)
}

// isRetryableTransportError implements the error axis of the transport-error
// retry allow-list: connection resets and network timeouts are retryable;
// everything else (DNS NotFound, TLS failures, context cancellation/deadline,
// EOF, connection refused) is not. context.DeadlineExceeded also satisfies
// net.Error.Timeout(), so the cancellation/deadline deny-check must run
// before the timeout allow-check.
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

// isReplayableRequest implements the request axis of the transport-error
// retry allow-list, mirroring net/http.Transport's own isReplayable: safe
// methods (or no method set) are always replayable; other methods are
// replayable only when they carry an Idempotency-Key or X-Idempotency-Key
// header (checked by presence, not value).
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
