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

func Test_isReplayableRequest(t *testing.T) {
	getBody := func() (io.ReadCloser, error) { return http.NoBody, nil }

	newReq := func(method string, body io.Reader, hasGetBody bool, headers map[string]string) *http.Request {
		req, err := http.NewRequest(method, "http://example.com", body)
		require.NoError(t, err)
		if hasGetBody {
			req.GetBody = getBody
		} else {
			req.GetBody = nil
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req
	}

	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"GET nil body", newReq(http.MethodGet, nil, false, nil), true},
		{"empty method", newReq("", nil, false, nil), true},
		{"HEAD", newReq(http.MethodHead, nil, false, nil), true},
		{"OPTIONS", newReq(http.MethodOptions, nil, false, nil), true},
		{"TRACE", newReq(http.MethodTrace, nil, false, nil), true},
		{"POST no body", newReq(http.MethodPost, nil, false, nil), false},
		{"PUT with body and GetBody", newReq(http.MethodPut, bytes.NewReader([]byte("x")), true, nil), false},
		{"DELETE", newReq(http.MethodDelete, nil, false, nil), false},
		{"lowercase get", newReq("get", nil, false, nil), false},
		{
			"POST with body, GetBody, Idempotency-Key",
			newReq(http.MethodPost, bytes.NewReader([]byte("x")), true, map[string]string{"Idempotency-Key": "abc"}),
			true,
		},
		{
			"POST with X-Idempotency-Key",
			newReq(http.MethodPost, bytes.NewReader([]byte("x")), true, map[string]string{"X-Idempotency-Key": "abc"}),
			true,
		},
		{
			"Idempotency-Key present but empty",
			newReq(http.MethodPost, bytes.NewReader([]byte("x")), true, map[string]string{"Idempotency-Key": ""}),
			true,
		},
		{"GET with body, GetBody nil", newReq(http.MethodGet, bytes.NewReader([]byte("x")), false, nil), false},
		{
			"GET with http.NoBody",
			func() *http.Request {
				req := newReq(http.MethodGet, nil, false, nil)
				req.Body = http.NoBody
				return req
			}(),
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isReplayableRequest(tt.req))
		})
	}
}
