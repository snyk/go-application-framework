package uploadrevision_test

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
)

func TestCompressionRoundTripper_RoundTrip(t *testing.T) {
	t.Run("request without body", func(t *testing.T) {
		ctx := context.Background()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify no compression headers are set
			assert.Empty(t, r.Header.Get("Content-Encoding"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		crt := uploadrevision.NewCompressionRoundTripper(http.DefaultTransport)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
		require.NoError(t, err)

		resp, err := crt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("request with body gets compressed", func(t *testing.T) {
		ctx := context.Background()
		originalBody := "Hello, World! This is some test data that should be compressed."
		var receivedBody []byte

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			assert.Empty(t, r.Header.Get("Content-Length"))
			assert.Equal(t, int64(-1), r.ContentLength)

			gzipReader, err := gzip.NewReader(r.Body)
			require.NoError(t, err)
			defer gzipReader.Close()

			receivedBody, err = io.ReadAll(gzipReader)
			require.NoError(t, err)

			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		crt := uploadrevision.NewCompressionRoundTripper(http.DefaultTransport)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader(originalBody))
		require.NoError(t, err)

		resp, err := crt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		assert.Equal(t, originalBody, string(receivedBody))
	})

	t.Run("preserves existing headers except Content-Length", func(t *testing.T) {
		ctx := context.Background()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer token123", r.Header.Get("Authorization"))
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			assert.Empty(t, r.Header.Get("Content-Length"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		crt := uploadrevision.NewCompressionRoundTripper(http.DefaultTransport)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader(`{"key":"value"}`))
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token123")
		req.Header.Set("Content-Length", "15")

		resp, err := crt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("wraps underlying transport errors", func(t *testing.T) {
		ctx := context.Background()
		failingTransport := &failingRoundTripper{err: assert.AnError}
		crt := uploadrevision.NewCompressionRoundTripper(failingTransport)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com", strings.NewReader("test"))
		require.NoError(t, err)

		_, err = crt.RoundTrip(req)
		assert.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError)
	})
}

// failingRoundTripper is a test helper that always returns an error.
type failingRoundTripper struct {
	err error
}

func (f *failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}
