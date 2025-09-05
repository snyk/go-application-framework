package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"

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
	default:
		err = cli.NewGeneralCLIFailureError(detail, cause)
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
