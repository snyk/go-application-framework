package contributor_capture_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestPeekResponseBody_restoresBodyOnReadError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read failed")
	prefix := []byte(`{"uri":"partial`)
	body := &errAfterReadCloser{prefix: append([]byte(nil), prefix...), err: wantErr}

	res := &http.Response{Body: body}
	_, _, err := cc.PeekResponseBody(res, cc.EndpointNone, 64<<10)
	require.ErrorIs(t, err, wantErr)

	got, readErr := io.ReadAll(res.Body)
	assert.Equal(t, prefix, got)
	require.ErrorIs(t, readErr, wantErr)

	require.NoError(t, res.Body.Close())
	assert.True(t, body.closed, "restored body must close the body it wraps")
}

func TestPeekResponseBody(t *testing.T) {
	t.Parallel()

	small := []byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)
	oversized := append([]byte(`{"uri":"partial-prefix`), bytes.Repeat([]byte("x"), 70<<10)...)

	tests := []struct {
		name          string
		contentLength int64
		body          []byte
		wantFullyRead bool
		wantPeekedLen int
	}{
		{
			name:          "full body despite inflated content length",
			contentLength: 70000,
			body:          small,
			wantFullyRead: true,
			wantPeekedLen: len(small),
		},
		{
			name:          "bounded prefix when oversized",
			body:          oversized,
			wantFullyRead: false,
			wantPeekedLen: 64 << 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := &http.Response{
				ContentLength: tt.contentLength,
				Body:          io.NopCloser(bytes.NewReader(tt.body)),
			}

			peeked, fullyRead, err := cc.PeekResponseBody(res, cc.EndpointNone, 64<<10)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFullyRead, fullyRead)
			assert.Len(t, peeked, tt.wantPeekedLen)
			assert.True(t, bytes.HasPrefix(tt.body, peeked), "peeked bytes must be a prefix of the real body")

			downstream, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.body, downstream, "the real body must still be readable in full, untruncated")
		})
	}
}

func TestPeekRequestBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		maxBytes  int64
		body      func() io.Reader
		expectLen int
	}{
		{
			name:      "full body when small",
			maxBytes:  64 << 10,
			body:      func() io.Reader { return strings.NewReader(`{"publish_report":true}`) },
			expectLen: 23,
		},
		{
			name:     "truncated on oversized",
			maxBytes: 64 << 10,
			body: func() io.Reader {
				return bytes.NewReader(append([]byte(`{"publish_report":true`), bytes.Repeat([]byte("x"), 70<<10)...))
			},
			expectLen: 64 << 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/v1/monitor", tt.body())
			require.NoError(t, err)

			got, err := cc.PeekRequestBody(req, tt.maxBytes)
			require.NoError(t, err)
			assert.Len(t, got, tt.expectLen)

			outgoing, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, outgoing, "peeking must leave the outgoing body untouched")
			assert.True(t, bytes.HasPrefix(outgoing, got), "peeked bytes must be a prefix of the real body")
		})
	}
}

func TestPeekRequestBody_skipsBodyThatCannotBeReplayed(t *testing.T) {
	t.Parallel()

	// A streaming body has no GetBody, so there is no copy to read without
	// stealing bytes from the outgoing request.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/v1/monitor", pr)
	require.NoError(t, err)
	require.Nil(t, req.GetBody)

	got, err := cc.PeekRequestBody(req, 64<<10)
	require.NoError(t, err)
	assert.Nil(t, got)
}

type errAfterReadCloser struct {
	prefix []byte
	err    error
	closed bool
}

func (r *errAfterReadCloser) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		if len(r.prefix) == 0 {
			return n, r.err
		}
		return n, nil
	}
	return 0, r.err
}

func (r *errAfterReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestPeekResponseBody_decodesGzippedDeeproxyBody(t *testing.T) {
	t.Parallel()

	plain := []byte(`{"status":"COMPLETE","uploadResult":{"projectId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}}`)
	var gzipped bytes.Buffer
	writer := gzip.NewWriter(&gzipped)
	_, err := writer.Write(plain)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	compressed := gzipped.Bytes()

	res := &http.Response{Body: io.NopCloser(bytes.NewReader(compressed))}
	peeked, fullyRead, err := cc.PeekResponseBody(res, cc.EndpointDeeproxyReport, 64<<10)
	require.NoError(t, err)
	assert.True(t, fullyRead)
	assert.Equal(t, plain, peeked)

	rest, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, compressed, rest)
}
