package middleware

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_isRetryableTransportError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare ECONNRESET", syscall.ECONNRESET, true},
		{
			"wrapped in OpError and SyscallError",
			&net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}},
			true,
		},
		{
			"wrapped in url.Error and OpError",
			&url.Error{Op: "Get", URL: "http://example.com", Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}},
			true,
		},
		{"Windows WSAECONNRESET", syscall.Errno(10054), true},
		{"os.ErrDeadlineExceeded", os.ErrDeadlineExceeded, true},
		{"DNS NotFound", &net.DNSError{IsNotFound: true}, false},
		{"DNS timeout", &net.DNSError{IsTimeout: true}, true},
		{"context canceled", context.Canceled, false},
		{"context deadline exceeded", context.DeadlineExceeded, false},
		{
			"url error wrapping deadline exceeded",
			&url.Error{Op: "Get", URL: "http://example.com", Err: context.DeadlineExceeded},
			false,
		},
		{"tls certificate verification error", &tls.CertificateVerificationError{}, false},
		{"ECONNREFUSED", syscall.ECONNREFUSED, false},
		{"io.EOF", io.EOF, false},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, false},
		{"generic error", errors.New("boom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRetryableTransportError(tt.err))
		})
	}
}

func Test_isRetryableRequest(t *testing.T) {
	getBody := func() (io.ReadCloser, error) { return http.NoBody, nil }

	newReq := func(method, path string, body io.Reader, hasGetBody bool) *http.Request {
		req, err := http.NewRequest(method, "http://example.com"+path, body)
		require.NoError(t, err)
		if hasGetBody {
			req.GetBody = getBody
		} else {
			req.GetBody = nil
		}
		return req
	}

	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"GET retried", newReq(http.MethodGet, "/", nil, false), true},
		{"plain POST not retried", newReq(http.MethodPost, "/", nil, false), false},
		{"POST to allow-listed path retried", newReq(http.MethodPost, "/v1/test-dep-graph", nil, false), true},
		{"POST to near-miss path not retried", newReq(http.MethodPost, "/v1/test-dep-graph-something", nil, false), false},
		{"POST to multi-segment allow-listed path retried", newReq(http.MethodPost, "/verify/token", nil, false), true},
		{"POST to multi-segment path nested under org retried", newReq(http.MethodPost, "/orgs/123/verify/token", nil, false), true},
		{"monitor path not retried", newReq(http.MethodPost, "/v1/monitor/npm", nil, false), false},
		{"body without GetBody not retried even on allow-listed path", newReq(http.MethodPost, "/v1/test-dep-graph", bytes.NewReader([]byte("x")), false), false},
		{"body with GetBody retried on allow-listed path", newReq(http.MethodPost, "/v1/test-dep-graph", bytes.NewReader([]byte("x")), true), true},
		{
			"GET with http.NoBody",
			func() *http.Request {
				req := newReq(http.MethodGet, "/", nil, false)
				req.Body = http.NoBody
				return req
			}(),
			true,
		},
	}

	config := configuration.NewWithOpts()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRetryableRequest(tt.req, config))
		})
	}
}

func Test_isRetryableRequest_ConfiguredAllowlistReplacesDefault(t *testing.T) {
	newReq := func(method, path string) *http.Request {
		req, err := http.NewRequest(method, "http://example.com"+path, nil)
		require.NoError(t, err)
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return req
	}

	config := configuration.NewWithOpts()
	config.Set(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS, []string{"custom"})

	assert.True(t, isRetryableRequest(newReq(http.MethodPost, "/v1/custom/npm"), config), "consumer-configured segment must be allowed")
	assert.False(t, isRetryableRequest(newReq(http.MethodPost, "/v1/test-dep-graph"), config), "a consumer-supplied allow-list replaces, not merges with, the default")
}

func Test_isRetryableRequest_ExplicitEmptyAllowlistOnlyAllowsSafeMethods(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com/v1/test-dep-graph", nil)
	require.NoError(t, err)
	req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }

	config := configuration.NewWithOpts()
	config.Set(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS, []string{})

	assert.False(t, isRetryableRequest(req, config), "an explicit empty allow-list means no unsafe-method path is retryable, the opposite of the old empty-deny-list meaning")

	getReq, err := http.NewRequest(http.MethodGet, "http://example.com/v1/test-dep-graph", nil)
	require.NoError(t, err)
	assert.True(t, isRetryableRequest(getReq, config), "safe methods retry regardless of the allow-list")
}
