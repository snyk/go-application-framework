package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

// NetworkStackErrorHandlerMiddleware is a middleware that handles network errors that are not yet error catalog errors.
type NetworkStackErrorHandlerMiddleware struct {
	next       http.RoundTripper
	errHandler networktypes.ErrorHandlerFunc
}

func NewNetworkStackErrorHandlerMiddleware(roundTriper http.RoundTripper, errHandler networktypes.ErrorHandlerFunc) *NetworkStackErrorHandlerMiddleware {
	return &NetworkStackErrorHandlerMiddleware{
		next:       roundTriper,
		errHandler: errHandler,
	}
}

func (ns *NetworkStackErrorHandlerMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := ns.next.RoundTrip(req)

	return res, ns.handleError(err, req)
}

func (ns *NetworkStackErrorHandlerMiddleware) handleError(err error, req *http.Request) error {
	if err != nil {
		// handle error that are not yet error catalog errors
		var snykError snyk_errors.Error
		if !errors.As(err, &snykError) {
			err = ns.categorizeNetworkError(err, req)
		}

		err = ns.errHandler(err, req.Context())
	}

	return err
}

// categorizeNetworkError categorizes network errors using Go's type system
func (ns *NetworkStackErrorHandlerMiddleware) categorizeNetworkError(err error, req *http.Request) error {
	detail := err.Error()
	cause := snyk_errors.WithCause(err)

	switch {
	// Checking proxy connection errors first to prevent the more generic errors from obfuscating the proxy presence.
	case ns.isProxyConnectionError(err):
		err = cli.NewProxyConnectionError(detail, cause)
	case ns.isDNSError(err):
		err = cli.NewDNSResolutionError(detail, cause)
	case ns.isTimeoutError(err):
		err = cli.NewConnectionTimeoutError(detail, cause)
	case ns.isNetworkUnreachableError(err):
		err = cli.NewNetworkUnreachableError(detail, cause)
	case ns.isTLSError(err):
		err = cli.NewTLSCertificateError(detail, cause)
	case ns.isConnectionRefusedError(err):
		err = cli.NewConnectionRefusedError(detail, cause)
	case ns.isConnectionResetError(err):
		err = cli.NewConnectionResetError(detail, cause)
	default:
		err = cli.NewGenericNetworkError(detail, cause)
	}

	err = addRequestDataToErr(err, req)
	return err
}

func (ns *NetworkStackErrorHandlerMiddleware) isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

func (ns *NetworkStackErrorHandlerMiddleware) isTimeoutError(err error) bool {
	if os.IsTimeout(err) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return true
	}

	return false
}

func (ns *NetworkStackErrorHandlerMiddleware) isTLSError(err error) bool {
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}

	var certVerificationErr *tls.CertificateVerificationError
	if errors.As(err, &certVerificationErr) {
		return true
	}

	var recordHeaderErr *tls.RecordHeaderError
	if errors.As(err, &recordHeaderErr) {
		return true
	}

	var echRejectionErr *tls.ECHRejectionError
	if errors.As(err, &echRejectionErr) {
		return true
	}

	var certInvalidErr *x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return true
	}

	var hostnameErr *x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var unknownAuthorityErr *x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var constraintViolationErr *x509.ConstraintViolationError
	if errors.As(err, &constraintViolationErr) {
		return true
	}

	var insecureAlgorithmErr *x509.InsecureAlgorithmError
	if errors.As(err, &insecureAlgorithmErr) {
		return true
	}

	var systemRootsErr *x509.SystemRootsError
	if errors.As(err, &systemRootsErr) {
		return true
	}

	var unhandledCriticalExtErr *x509.UnhandledCriticalExtension
	return errors.As(err, &unhandledCriticalExtErr)
}

func (ns *NetworkStackErrorHandlerMiddleware) isConnectionRefusedError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return strings.Contains(strings.ToLower(opErr.Err.Error()), "connection refused")
	}
	return false
}

func (ns *NetworkStackErrorHandlerMiddleware) isNetworkUnreachableError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		errStr := strings.ToLower(opErr.Err.Error())
		return strings.Contains(errStr, "network is unreachable") ||
			strings.Contains(errStr, "no route to host") ||
			strings.Contains(errStr, "host is unreachable")
	}

	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "host is unreachable") ||
		strings.Contains(errStr, "connect: no route to host")
}

func (ns *NetworkStackErrorHandlerMiddleware) isConnectionResetError(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}

	// An EOF only means a reset when it comes off the network stack; the wrapped
	// round tripper is arbitrary and can surface io.ErrUnexpectedEOF for its own reasons.
	var opErr *net.OpError
	var urlErr *url.Error
	if errors.Is(err, io.ErrUnexpectedEOF) && (errors.As(err, &opErr) || errors.As(err, &urlErr)) {
		return true
	}

	// The Windows clauses match the WSAECONNRESET / WSAECONNABORTED message text,
	// which the net package surfaces instead of syscall.ECONNRESET / syscall.EPIPE.
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "forcibly closed") ||
		strings.Contains(errStr, "connection was aborted")
}

func (ns *NetworkStackErrorHandlerMiddleware) isProxyConnectionError(err error) bool {
	// net/http wraps a failed proxy hop as &net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "proxyconnect" {
		return true
	}

	// A CONNECT rejected with 407 surfaces as a bare error carrying the status text.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/407
	return strings.Contains(strings.ToLower(err.Error()), "proxy authentication required")
}
