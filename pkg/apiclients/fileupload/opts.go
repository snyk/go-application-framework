package fileupload

import (
	"io/fs"

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

// WithPathEncoder allows transforming each file's upload path (relative to the root
// directory) before it is sent, e.g. to URI-encode the path. It does not affect the
// filesystem path the file is read from.
func WithPathEncoder(encode func(path string) string) Option {
	return func(h *HTTPClient) {
		h.pathEncoder = encode
	}
}

// WithContentTranscoder allows wrapping each opened file before its content is streamed,
// e.g. to transcode the content to UTF-8. The returned file is read and closed by the client.
func WithContentTranscoder(transcode func(file fs.File) fs.File) Option {
	return func(h *HTTPClient) {
		h.contentTranscoder = transcode
	}
}
