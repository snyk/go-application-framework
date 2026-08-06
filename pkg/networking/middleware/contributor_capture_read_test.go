package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestReadResponseBody_restoresPrefixOnReadError(t *testing.T) {
	t.Parallel()

	prefix := []byte(`{"uri":"partial`)
	body := &errAfterReadCloser{prefix: append([]byte(nil), prefix...), err: errors.New("read failed")}

	res := &http.Response{Body: body}
	_, parseable, err := readResponseBody(res, 64<<10)
	require.Error(t, err)
	assert.False(t, parseable)

	got, readErr := io.ReadAll(res.Body)
	require.NoError(t, readErr)
	assert.Equal(t, prefix, got)
}

func TestReadResponseBody_capturesSmallBodyDespiteInflatedContentLength(t *testing.T) {
	t.Parallel()

	body := []byte(`{"uri":"https://app.snyk.io/org/acme/project/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/history/cccccccc-cccc-4ccc-8ccc-cccccccccccc"}`)
	res := &http.Response{
		ContentLength: 70000,
		Body:          io.NopCloser(bytes.NewReader(body)),
	}

	got, parseable, err := readResponseBody(res, 64<<10)
	require.NoError(t, err)
	assert.True(t, parseable)
	assert.Equal(t, body, got)

	downstream, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, body, downstream)
}
