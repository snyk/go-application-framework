package contributor_capture_test

import (
	"bytes"
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
	_, _, err := cc.PeekResponseBody(res, 64<<10)
	require.ErrorIs(t, err, wantErr)

	got, readErr := io.ReadAll(res.Body)
	assert.Equal(t, prefix, got)
	require.ErrorIs(t, readErr, wantErr)

	require.NoError(t, res.Body.Close())
	assert.True(t, body.closed, "restored body must close the body it wraps")
}

func TestPeekResponseBody_succeedsDespiteInflatedContentLength(t *testing.T) {
	t.Parallel()

	body := []byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)
	res := &http.Response{
		ContentLength: 70000,
		Body:          io.NopCloser(bytes.NewReader(body)),
	}

	got, fullyRead, err := cc.PeekResponseBody(res, 64<<10)
	require.NoError(t, err)
	assert.True(t, fullyRead)
	assert.Equal(t, body, got)

	downstream, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, body, downstream)
}

func TestPeekResponseBody_truncatesOversizedBodyButPreservesFullBody(t *testing.T) {
	t.Parallel()

	prefix := []byte(`{"uri":"partial-prefix`)
	padding := bytes.Repeat([]byte("x"), 70<<10) // above the 64 KiB limit used below
	wantBody := append(append([]byte(nil), prefix...), padding...)

	res := &http.Response{Body: io.NopCloser(bytes.NewReader(wantBody))}
	peeked, fullyRead, err := cc.PeekResponseBody(res, 64<<10)
	require.NoError(t, err)
	assert.False(t, fullyRead)
	assert.Equal(t, int64(64<<10), int64(len(peeked)), "should return a bounded prefix")

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, wantBody, gotBody, "the real body must still be readable in full, untruncated")
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
