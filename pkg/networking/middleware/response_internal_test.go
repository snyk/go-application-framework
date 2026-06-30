package middleware

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type trackingBody struct {
	io.ReadCloser
	closed bool
}

func (tb *trackingBody) Close() error {
	tb.closed = true
	return tb.ReadCloser.Close()
}

func Test_getErrorList_closesBody(t *testing.T) {
	validJSON := `{"jsonapi":{"version":"1.0"},"errors":[{"status":"400","detail":"bad request","title":"Bad Request"}]}`

	t.Run("closes body after successful read", func(t *testing.T) {
		tb := &trackingBody{ReadCloser: io.NopCloser(strings.NewReader(validJSON))}
		res := &http.Response{Body: tb}

		getErrorList(res)

		assert.True(t, tb.closed, "original body must be closed after reading")
	})

	t.Run("closes body when JSON parsing fails", func(t *testing.T) {
		tb := &trackingBody{ReadCloser: io.NopCloser(strings.NewReader("not json"))}
		res := &http.Response{Body: tb}

		getErrorList(res)

		assert.True(t, tb.closed, "original body must be closed even when JSON parsing fails")
	})
}
