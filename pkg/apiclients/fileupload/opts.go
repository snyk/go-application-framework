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

// PathEncoder transforms a file's upload path, relative to the root directory. The encoded
// path is the one filtered by the path length limit and reported for skipped files.
type PathEncoder func(path string) string

// ContentTranscoder wraps an opened file before its content is streamed. The client closes
// both the returned file and the file it was opened from.
//
// Stat is called more than once, before any content is read. It must report the size and mode
// of the transcoded content, always report the same size, and must not consume the content.
type ContentTranscoder func(file fs.File) (fs.File, error)

// WithPathEncoder allows encoding each file's upload path before it is sent, e.g. to URI-encode
// it. It does not affect the filesystem path the file is read from.
func WithPathEncoder(encode PathEncoder) Option {
	return func(h *HTTPClient) {
		h.pathEncoder = encode
	}
}

// WithContentTranscoder allows transcoding each file's content before it is streamed, e.g. to
// UTF-8. Files the transcoder fails on are skipped.
func WithContentTranscoder(transcode ContentTranscoder) Option {
	return func(h *HTTPClient) {
		h.contentTranscoder = transcode
	}
}
