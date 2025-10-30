package uploadrevision

import (
	"compress/gzip"
	"io"
	"net/http"
)

// CompressionRoundTripper is an http.RoundTripper that automatically compresses
// request bodies using gzip compression. It wraps another RoundTripper and adds
// Content-Encoding: gzip header while removing Content-Length to allow proper
// compression handling.
type CompressionRoundTripper struct {
	defaultRoundTripper http.RoundTripper
}

// NewCompressionRoundTripper creates a new CompressionRoundTripper that wraps
// the provided RoundTripper. If drt is nil, http.DefaultTransport is used.
// All HTTP requests with a body will be automatically compressed using gzip.
func NewCompressionRoundTripper(drt http.RoundTripper) *CompressionRoundTripper {
	rt := drt
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &CompressionRoundTripper{rt}
}

// compressRequestBody wraps the given reader with gzip compression.
func compressRequestBody(body io.Reader) io.ReadCloser {
	pipeReader, pipeWriter := io.Pipe()

	go func() {
		var err error
		gzWriter := gzip.NewWriter(pipeWriter)

		_, err = io.Copy(gzWriter, body)

		if closeErr := gzWriter.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		pipeWriter.CloseWithError(err)
	}()

	return pipeReader
}

// RoundTrip implements the http.RoundTripper interface. It compresses the request
// body using gzip if a body is present, sets the Content-Encoding header to "gzip",
// and removes the Content-Length header to allow Go's HTTP client to calculate
// the correct length after compression. Requests without a body are passed through
// unchanged to the wrapped RoundTripper.
func (crt *CompressionRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body == nil || r.Body == http.NoBody {
		//nolint:wrapcheck // No need to wrap the error here.
		return crt.defaultRoundTripper.RoundTrip(r)
	}

	compressedBody := compressRequestBody(r.Body)

	r.Body = compressedBody
	r.Header.Set(ContentEncoding, "gzip")
	r.Header.Del(ContentLength)
	r.ContentLength = -1 // Let Go calculate the length

	//nolint:wrapcheck // No need to wrap the error here.
	return crt.defaultRoundTripper.RoundTrip(r)
}
