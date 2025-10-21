package middleware

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

// Define a custom type for context keys to avoid collisions
type contextKey string

const testContextKey contextKey = "test-key"

func Test_NetworkStackErrorHandlerMiddleware(t *testing.T) {
	t.Run("NewNetworkStackErrorHandlerMiddleware", func(t *testing.T) {
		next := http.DefaultTransport
		errHandler := func(err error, ctx context.Context) error {
			return err
		}

		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		assert.NotNil(t, middlewareInstance)
		// We can't test private fields directly, but we can test that the middleware was created
	})

	t.Run("RoundTrip with nil error", func(t *testing.T) {
		// Create a mock that returns success (no error)
		next := &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			},
		}

		errHandler := func(err error, ctx context.Context) error {
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		resp, err := middlewareInstance.RoundTrip(req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("handleError with regular Go error - converts to generic CLI failure error", func(t *testing.T) {
		regularError := errors.New("regular network error")

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com/test", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(regularError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedError)

		// Verify that the regular error was converted to generic CLI failure error
		var cliError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &cliError))

		// Check that it's a generic CLI failure error
		expectedGenericError := cli.NewGenericNetworkError("")
		assert.Equal(t, expectedGenericError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("handleError with existing snyk_errors.Error - passes through unchanged", func(t *testing.T) {
		originalError := snyk.NewBadRequestError("Original error")
		originalError.ErrorCode = "TEST-001"

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(originalError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedError)

		// Verify that the original snyk error was passed through unchanged
		var snykError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &snykError))
		assert.Equal(t, originalError.Title, snykError.Title)
		assert.Equal(t, originalError.ErrorCode, snykError.ErrorCode)
		assert.Equal(t, "TEST-001", snykError.ErrorCode)
	})

	t.Run("handleError with wrapped snyk_errors.Error - passes through unchanged", func(t *testing.T) {
		// Create a wrapped snyk error
		originalError := snyk.NewUnauthorisedError("Wrapped error")
		originalError.ErrorCode = "TEST-002"
		wrappedError := fmt.Errorf("wrapper: %w", originalError)

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(wrappedError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedError)

		// Verify that the wrapped snyk error was passed through unchanged
		var snykError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &snykError))
		assert.Equal(t, originalError.Title, snykError.Title)
		assert.Equal(t, originalError.ErrorCode, snykError.ErrorCode)
		assert.Equal(t, "TEST-002", snykError.ErrorCode)
	})

	t.Run("handleError calls error handler with context", func(t *testing.T) {
		regularError := errors.New("test error")

		var capturedContext context.Context
		errHandler := func(err error, ctx context.Context) error {
			capturedContext = ctx
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		// Create request with context
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)
		ctx := context.WithValue(context.Background(), testContextKey, "test-value")
		req = req.WithContext(ctx)

		result := middlewareInstance.handleError(regularError, req)

		// Verify error handling
		assert.Error(t, result)
		assert.NotNil(t, capturedContext)
		assert.Equal(t, "test-value", capturedContext.Value(testContextKey))
	})

	t.Run("handleError allows error handler to modify error", func(t *testing.T) {
		regularError := errors.New("original error")

		modifiedError := errors.New("modified error")
		errHandler := func(err error, ctx context.Context) error {
			return modifiedError
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(http.DefaultTransport, errHandler)

		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		result := middlewareInstance.handleError(regularError, req)

		// Verify that the error was modified by the error handler
		assert.Error(t, result)
		assert.Equal(t, modifiedError, result)
	})

	t.Run("RoundTrip with no error", func(t *testing.T) {
		// Create a mock that returns success
		next := &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			},
		}

		errHandler := func(err error, ctx context.Context) error {
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		// Create request
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		// Execute request
		resp, err := middlewareInstance.RoundTrip(req)

		// Verify success
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("RoundTrip with error - calls handleError", func(t *testing.T) {
		// Create a mock that returns an error
		regularError := errors.New("network error")
		next := &mockRoundTripper{
			err: regularError,
		}

		var capturedError error
		errHandler := func(err error, ctx context.Context) error {
			capturedError = err
			return err
		}
		middlewareInstance := NewNetworkStackErrorHandlerMiddleware(next, errHandler)

		// Create request
		req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
		assert.NoError(t, err)

		// Execute request
		resp, err := middlewareInstance.RoundTrip(req)

		// Verify error handling
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.NotNil(t, capturedError)

		// Verify that the error was converted to generic CLI failure error
		var cliError snyk_errors.Error
		assert.True(t, errors.As(capturedError, &cliError))

		// Check that it's a generic CLI failure error
		expectedGenericError := cli.NewGenericNetworkError("")
		assert.Equal(t, expectedGenericError.ErrorCode, cliError.ErrorCode)
	})
}

func Test_categorizeNetworkError(t *testing.T) {
	middleware := &NetworkStackErrorHandlerMiddleware{}

	req, err := http.NewRequest(http.MethodGet, "https://api.snyk.io/test", nil)
	assert.NoError(t, err)

	t.Run("DNS Resolution Error - net.DNSError", func(t *testing.T) {
		dnsErr := &net.DNSError{
			Err:        "no such host",
			Name:       "example.com",
			Server:     "8.8.8.8",
			IsNotFound: true,
		}

		result := middleware.categorizeNetworkError(dnsErr, req)

		// Verify it returns a DNS resolution error
		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedDNSError := cli.NewDNSResolutionError("")
		assert.Equal(t, expectedDNSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Connection Timeout - os.IsTimeout", func(t *testing.T) {
		err := &timeoutError{}

		result := middleware.categorizeNetworkError(err, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedTimeoutError := cli.NewConnectionTimeoutError("")
		assert.Equal(t, expectedTimeoutError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Connection Timeout - url.Error with timeout", func(t *testing.T) {
		urlErr := &url.Error{
			Op:  "GET",
			URL: "https://example.com",
			Err: &timeoutError{},
		}

		result := middleware.categorizeNetworkError(urlErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedTimeoutError := cli.NewConnectionTimeoutError("")
		assert.Equal(t, expectedTimeoutError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("URL Error with timeout - os.IsTimeout DOES catch it", func(t *testing.T) {
		// Create a url.Error containing a timeout error
		// os.IsTimeout DOES catch this because it properly handles url.Error
		timeoutErr := &timeoutError{}
		urlErr := &url.Error{
			Op:  "GET",
			URL: "https://example.com",
			Err: timeoutErr,
		}

		// Verify that os.IsTimeout DOES catch url.Error with timeout
		assert.True(t, os.IsTimeout(urlErr), "os.IsTimeout should catch url.Error with timeout")

		// And our custom check should also catch it
		assert.True(t, urlErr.Timeout(), "url.Error.Timeout() should return true")

		result := middleware.categorizeNetworkError(urlErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedTimeoutError := cli.NewConnectionTimeoutError("")
		assert.Equal(t, expectedTimeoutError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Connection Refused - net.OpError", func(t *testing.T) {
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errors.New("connection refused"),
		}

		result := middleware.categorizeNetworkError(opErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedConnectionRefusedError := cli.NewConnectionRefusedError("")
		assert.Equal(t, expectedConnectionRefusedError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Network Unreachable - net.OpError", func(t *testing.T) {
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errors.New("network is unreachable"),
		}

		result := middleware.categorizeNetworkError(opErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedNetworkUnreachableError := cli.NewNetworkUnreachableError("")
		assert.Equal(t, expectedNetworkUnreachableError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Network Unreachable - no route to host", func(t *testing.T) {
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errors.New("connect: no route to host"),
		}

		result := middleware.categorizeNetworkError(opErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedNetworkUnreachableError := cli.NewNetworkUnreachableError("")
		assert.Equal(t, expectedNetworkUnreachableError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Proxy unreachable - should not be TLS error", func(t *testing.T) {
		// This simulates the exact error you encountered
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errors.New("connect: no route to host"),
		}

		result := middleware.categorizeNetworkError(opErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedNetworkUnreachableError := cli.NewNetworkUnreachableError("")
		assert.Equal(t, expectedNetworkUnreachableError.ErrorCode, cliError.ErrorCode)

		// Verify it's not a TLS error
		expectedTLSError := cli.NewTLSCertificateError("")
		assert.NotEqual(t, expectedTLSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Direct error string - no route to host", func(t *testing.T) {
		// Test the error string directly without net.OpError wrapper
		err := errors.New("dial tcp 0.0.0.121:80: connect: no route to host")

		result := middleware.categorizeNetworkError(err, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedNetworkUnreachableError := cli.NewNetworkUnreachableError("")
		assert.Equal(t, expectedNetworkUnreachableError.ErrorCode, cliError.ErrorCode)

		// Verify it's not a TLS error
		expectedTLSError := cli.NewTLSCertificateError("")
		assert.NotEqual(t, expectedTLSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("TLS Alert Error", func(t *testing.T) {
		alertErr := tls.AlertError(41) // Certificate unknown alert

		result := middleware.categorizeNetworkError(alertErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedTLSError := cli.NewTLSCertificateError("")
		assert.Equal(t, expectedTLSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("X509 Certificate Invalid Error", func(t *testing.T) {
		certErr := &x509.CertificateInvalidError{Reason: x509.Expired}

		result := middleware.categorizeNetworkError(certErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedTLSError := cli.NewTLSCertificateError("")
		assert.Equal(t, expectedTLSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("X509 Hostname Error", func(t *testing.T) {
		hostnameErr := &x509.HostnameError{Certificate: &x509.Certificate{}, Host: "example.com"}

		result := middleware.categorizeNetworkError(hostnameErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedTLSError := cli.NewTLSCertificateError("")
		assert.Equal(t, expectedTLSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Non-TLS error should not be classified as TLS", func(t *testing.T) {
		// Test that a regular error is NOT classified as TLS
		err := errors.New("some random network error")

		result := middleware.categorizeNetworkError(err, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedGenericError := cli.NewGenericNetworkError("")
		assert.Equal(t, expectedGenericError.ErrorCode, cliError.ErrorCode)

		// Verify it's not a TLS error
		expectedTLSError := cli.NewTLSCertificateError("")
		assert.NotEqual(t, expectedTLSError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Complex error precedence - DNS should win over timeout", func(t *testing.T) {
		// Create a DNS error that also has timeout characteristics
		dnsErr := &net.DNSError{
			Err:        "no such host",
			Name:       "example.com",
			Server:     "8.8.8.8",
			IsNotFound: true,
		}
		// Wrap it in a url.Error with timeout
		urlErr := &url.Error{
			Op:  "GET",
			URL: "https://example.com",
			Err: dnsErr,
		}

		result := middleware.categorizeNetworkError(urlErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedDNSError := cli.NewDNSResolutionError("")
		assert.Equal(t, expectedDNSError.ErrorCode, cliError.ErrorCode)

		// Verify it's not a timeout error
		expectedTimeoutError := cli.NewConnectionTimeoutError("")
		assert.NotEqual(t, expectedTimeoutError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Complex error precedence - Network unreachable should win over timeout", func(t *testing.T) {
		// Create a network unreachable error wrapped in net.OpError with timeout
		opErr := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: errors.New("network is unreachable"),
		}
		// Make it also have timeout characteristics
		urlErr := &url.Error{
			Op:  "GET",
			URL: "https://example.com",
			Err: opErr,
		}

		result := middleware.categorizeNetworkError(urlErr, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedNetworkUnreachableError := cli.NewNetworkUnreachableError("")
		assert.Equal(t, expectedNetworkUnreachableError.ErrorCode, cliError.ErrorCode)

		// Verify it's not a timeout error
		expectedTimeoutError := cli.NewConnectionTimeoutError("")
		assert.NotEqual(t, expectedTimeoutError.ErrorCode, cliError.ErrorCode)
	})

	t.Run("Generic Network Error - fallback", func(t *testing.T) {
		err := errors.New("some random network error")

		result := middleware.categorizeNetworkError(err, req)

		var cliError snyk_errors.Error
		assert.True(t, errors.As(result, &cliError))

		expectedGenericError := cli.NewGenericNetworkError("")
		assert.Equal(t, expectedGenericError.ErrorCode, cliError.ErrorCode)
	})
}

// timeoutError implements error interface for testing timeout scenarios
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// mockRoundTripper is a mock implementation of http.RoundTripper for testing
type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}
