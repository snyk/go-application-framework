package fileupload

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

// Option allows customizing the Client during construction.
type Option func(*HTTPClient)

// WithUploadRevisionSealableClient allows injecting a custom low-level client (primarily for testing).
func WithUploadRevisionSealableClient(client uploadrevision.SealableClient) Option {
	return func(c *HTTPClient) {
		c.uploadRevisionSealableClient = client
	}
}

// WithLogger allows injecting a custom logger instance.
func WithLogger(logger *zerolog.Logger) Option {
	return func(h *HTTPClient) {
		h.logger = logger
	}
}

// PathEncoder transforms a file's upload path, relative to the root directory. The encoded
// path is the one filtered by the path length limit and reported for skipped files.
type PathEncoder func(path string) string

// ContentTranscoder transforms a file's content before it is uploaded. The returned content is
// the one filtered by the file size limit and uploaded.
type ContentTranscoder func(content []byte) ([]byte, error)

// WithPathEncoder allows encoding each file's upload path before it is sent, e.g. to URI-encode
// it. It does not affect the filesystem path the file is read from.
func WithPathEncoder(encode PathEncoder) Option {
	return func(h *HTTPClient) {
		h.pathEncoder = encode
	}
}

// WithContentTranscoder allows transcoding each file's content before it is uploaded, e.g. to
// UTF-8. Files the transcoder fails on are skipped.
func WithContentTranscoder(transcode ContentTranscoder) Option {
	return func(h *HTTPClient) {
		h.contentTranscoder = transcode
	}
}
