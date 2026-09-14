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
		{"bare EPIPE", syscall.EPIPE, true},
		{
			"io.ErrUnexpectedEOF wrapped in net.OpError",
			&net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF},
			true,
		},
		{
			"io.ErrUnexpectedEOF wrapped in url.Error",
			&url.Error{Op: "Get", URL: "http://example.com", Err: io.ErrUnexpectedEOF},
			true,
		},
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
		{"POST to allow-listed path retried", newReq(http.MethodPost, "/v1/declared", nil, false), true},
		{"POST to near-miss path not retried", newReq(http.MethodPost, "/v1/declared-something", nil, false), false},
		{"POST to multi-segment allow-listed path retried", newReq(http.MethodPost, "/declared/nested", nil, false), true},
		{"POST to multi-segment path nested under org retried", newReq(http.MethodPost, "/orgs/123/declared/nested", nil, false), true},
		{"POST to undeclared path not retried", newReq(http.MethodPost, "/v1/undeclared/npm", nil, false), false},
		{"body with GetBody retried on allow-listed path", newReq(http.MethodPost, "/v1/declared", bytes.NewReader([]byte("x")), true), true},
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
	config.Set(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS, []string{"declared", "declared/nested"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRetryableRequest(tt.req, config))
		})
	}
}

func Test_isRetryableRequest_AllowlistComesOnlyFromConfiguration(t *testing.T) {
	newReq := func(path string) *http.Request {
		req, err := http.NewRequest(http.MethodPost, "http://example.com"+path, nil)
		require.NoError(t, err)
		req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return req
	}

	unset := configuration.NewWithOpts()
	assert.False(t, isRetryableRequest(newReq("/v1/custom/npm"), unset), "the framework contributes no paths of its own")

	configured := configuration.NewWithOpts()
	configured.Set(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS, []string{"custom"})
	assert.True(t, isRetryableRequest(newReq("/v1/custom/npm"), configured), "consumer-configured segment must be allowed")
	assert.False(t, isRetryableRequest(newReq("/v1/other"), configured), "only what the consumer declared is allowed")
}

func Test_isAllowedPath_EmptyAllowlistMatchesNothing(t *testing.T) {
	for _, path := range []string{"", "/", "/v1/declared", "/v1/declared/nested"} {
		assert.False(t, isAllowedPath(path, nil), "path %q", path)
		assert.False(t, isAllowedPath(path, []string{}), "path %q", path)
	}
}

func Test_isAllowedPath_BlankEntriesMatchNothing(t *testing.T) {
	tests := []struct {
		name    string
		allowed []string
		want    bool
	}{
		{"empty entry", []string{""}, false},
		{"whitespace entry", []string{"  "}, false},
		{"blank entry alongside a non-matching entry", []string{"", "declared/nested"}, false},
		{"blank entry alongside a matching entry", []string{"", "monitor"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAllowedPath("/v1/monitor/npm", tt.allowed))
		})
	}
}

func Test_isRetryableRequest_ExplicitEmptyAllowlistOnlyAllowsSafeMethods(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://example.com/v1/declared", nil)
	require.NoError(t, err)
	req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }

	config := configuration.NewWithOpts()
	config.Set(configuration.NETWORK_REQUEST_RETRY_ALLOWED_PATHS, []string{})

	assert.False(t, isRetryableRequest(req, config), "an explicit empty allow-list means no unsafe-method path is retryable, the opposite of the old empty-deny-list meaning")

	getReq, err := http.NewRequest(http.MethodGet, "http://example.com/v1/declared", nil)
	require.NoError(t, err)
	assert.True(t, isRetryableRequest(getReq, config), "safe methods retry regardless of the allow-list")
}

func Test_isAllowedPath_LeadingSlashNormalized(t *testing.T) {
	// Entries with leading slashes are trimmed and match the same paths as entries without leading slashes.
	// This is the normalized behavior: "/declared" and "declared" are equivalent.
	tests := []struct {
		name    string
		path    string
		allowed []string
		want    bool
	}{
		{"bare segment matches anywhere in path", "/v1/declared", []string{"declared"}, true},
		{"leading slash entry matches same paths as bare entry", "/v1/declared", []string{"/declared"}, true},
		{"leading slash entry matches multi-segment paths", "/v1/declared/nested", []string{"/declared/nested"}, true},
		{"leading slash entry still avoids near-misses", "/v1/declared-something", []string{"/declared"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAllowedPath(tt.path, tt.allowed))
		})
	}
}
