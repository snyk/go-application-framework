package contributor_capture_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

func TestReadRequestBody_restoresBodyOnReadError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read failed")
	prefix := []byte(`{"uri":"partial`)
	body := &errAfterReadCloser{prefix: append([]byte(nil), prefix...), err: wantErr}

	req := &http.Request{Body: body}
	_, err := cc.ReadRequestBody(req, 64<<10)
	require.ErrorIs(t, err, wantErr)

	got, readErr := io.ReadAll(req.Body)
	assert.Equal(t, prefix, got)
	require.ErrorIs(t, readErr, wantErr)

	require.NoError(t, req.Body.Close())
	assert.True(t, body.closed, "restored body must close the body it wraps")
}

func TestReadResponseBody_restoresBodyOnReadError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read failed")
	prefix := []byte(`{"uri":"partial`)
	body := &errAfterReadCloser{prefix: append([]byte(nil), prefix...), err: wantErr}

	res := &http.Response{Body: body}
	_, err := cc.ReadResponseBody(res, 64<<10)
	require.ErrorIs(t, err, wantErr)

	got, readErr := io.ReadAll(res.Body)
	assert.Equal(t, prefix, got)
	require.ErrorIs(t, readErr, wantErr)

	require.NoError(t, res.Body.Close())
	assert.True(t, body.closed, "restored body must close the body it wraps")
}

func TestReadRequestBody_succeedsDespiteInflatedContentLength(t *testing.T) {
	t.Parallel()

	body := []byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)
	req := &http.Request{
		ContentLength: 70000,
		Body:          io.NopCloser(bytes.NewReader(body)),
	}

	got, err := cc.ReadRequestBody(req, 64<<10)
	require.NoError(t, err)
	assert.Equal(t, body, got)

	downstream, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, downstream)
}

func TestReadResponseBody_succeedsDespiteInflatedContentLength(t *testing.T) {
	t.Parallel()

	body := []byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)
	res := &http.Response{
		ContentLength: 70000,
		Body:          io.NopCloser(bytes.NewReader(body)),
	}

	got, err := cc.ReadResponseBody(res, 64<<10)
	require.NoError(t, err)
	assert.Equal(t, body, got)

	downstream, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, body, downstream)
}

func TestReadRequestBody_returnsErrBodyTooLargeButPreservesFullBody(t *testing.T) {
	t.Parallel()

	prefix := []byte(`{"uri":"partial-prefix`)
	padding := make([]byte, 70<<10) // above the 64 KiB limit used below
	for i := range padding {
		padding[i] = 'x'
	}
	wantBody := append(append([]byte(nil), prefix...), padding...)

	req := &http.Request{Body: io.NopCloser(bytes.NewReader(wantBody))}
	peeked, err := cc.ReadRequestBody(req, 64<<10)
	require.ErrorIs(t, err, cc.ErrBodyTooLarge)
	assert.Nil(t, peeked)

	gotBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, wantBody, gotBody, "the real body must reach whoever reads it next, untruncated")
}

func TestReadResponseBody_returnsErrBodyTooLargeButPreservesFullBody(t *testing.T) {
	t.Parallel()

	prefix := []byte(`{"uri":"partial-prefix`)
	padding := make([]byte, 70<<10) // above the 64 KiB limit used below
	for i := range padding {
		padding[i] = 'x'
	}
	wantBody := append(append([]byte(nil), prefix...), padding...)

	res := &http.Response{Body: io.NopCloser(bytes.NewReader(wantBody))}
	peeked, err := cc.ReadResponseBody(res, 64<<10)
	require.ErrorIs(t, err, cc.ErrBodyTooLarge)
	assert.Nil(t, peeked)

	gotBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, wantBody, gotBody, "the real body must still be readable in full, untruncated")
}

func TestReadRequestBody_restoredBodyStaysRewindable(t *testing.T) {
	t.Parallel()

	body := []byte(`{"publish_report":true}`)
	req := &http.Request{Body: io.NopCloser(bytes.NewReader(body))}

	_, err := cc.ReadRequestBody(req, 64<<10)
	require.NoError(t, err)

	seeker, ok := req.Body.(io.ReadSeeker)
	require.True(t, ok, "restored body must still satisfy io.ReadSeeker")

	first, err := io.ReadAll(seeker)
	require.NoError(t, err)
	assert.Equal(t, body, first)

	_, err = seeker.Seek(0, io.SeekStart)
	require.NoError(t, err)

	second, err := io.ReadAll(seeker)
	require.NoError(t, err)
	assert.Equal(t, body, second, "a rewound body must replay identically")
}

func TestReadResponseBody_restoredBodyStaysRewindable(t *testing.T) {
	t.Parallel()

	body := []byte(`{"data":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}}`)
	res := &http.Response{Body: io.NopCloser(bytes.NewReader(body))}

	_, err := cc.ReadResponseBody(res, 64<<10)
	require.NoError(t, err)

	seeker, ok := res.Body.(io.ReadSeeker)
	require.True(t, ok, "restored body must still satisfy io.ReadSeeker")

	_, err = seeker.Seek(0, io.SeekStart)
	require.NoError(t, err)

	got, err := io.ReadAll(seeker)
	require.NoError(t, err)
	assert.Equal(t, body, got)
}

func TestDecodeCaptureBody_gzipDeeproxyReport(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"status":"COMPLETE","uploadResult":{"projectId":"25bcb5ba-5b16-4f56-8620-4e3a508f67ed"}}`)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(raw)
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	decoded, err := cc.DecodeCaptureBody(buf.Bytes(), "gzip")
	require.NoError(t, err)
	assert.Equal(t, raw, decoded)
	assert.Equal(t, "25bcb5ba-5b16-4f56-8620-4e3a508f67ed", cc.ParseDeeproxyReportProjectID(decoded))
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
