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
//
// It cannot be combined with WithLargeFileUpload: the client then fails with
// ErrContentTranscoderWithLargeFileUpload.
func WithContentTranscoder(transcode ContentTranscoder) Option {
	return func(h *HTTPClient) {
		h.contentTranscoder = transcode
	}
}

// WithLargeFileUpload allows uploading files larger than the max file size in chunks of the max size.
// Chunks must be reassembled by the consumer itself.
//
// When enabled, every file is uploaded in chunks, including files smaller than the max file size,
// which result in a single chunk. Files are no longer uploaded in batches.
//
// Files are uploaded sequentially; only the chunks of a single file are uploaded in parallel.
// Uploading many small files is therefore slower than with the default batched upload, so
// enable this only when large files are expected.
//
// Each chunk is named "<path>_chunk_v1_NNNN", where <path> is the file path relative to the root path
// and NNNN is the 0-indexed chunk number, zero-padded to 4 digits (e.g. "src/big.bin_chunk_v1_0000").
// All chunks but the last have the max file size; the last one may be smaller. A file may consist of
// at most 10,000 chunks, and chunks must be at least 125 KB.
//
// The maximum size of a single file is 10 GB.
//
// It cannot be combined with WithContentTranscoder: the client then fails with
// ErrContentTranscoderWithLargeFileUpload.
//
// Chunk names are not escaped: a real file named like a chunk (e.g. "foo_chunk_v1_0000") collides with
// the chunks of the file "foo" if both are uploaded in the same revision.
func WithLargeFileUpload(enabled bool) Option {
	return func(h *HTTPClient) {
		h.largeFileUpload = enabled
	}
}
