package fileupload

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/filters"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
)

// Option allows customizing the Client during construction.
type Option func(*HTTPClient)

// WithUploadRevisionSealableClient allows injecting a custom low-level client (primarily for testing).
func WithUploadRevisionSealableClient(client uploadrevision.SealableClient) Option {
	return func(c *HTTPClient) {
		c.uploadRevisionSealableClient = client
	}
}

// WithFiltersClient allows injecting a custom low-level client (primarily for testing).
func WithFiltersClient(client filters.Client) Option {
	return func(c *HTTPClient) {
		c.filtersClient = client
	}
}

// WithLogger allows injecting a custom logger instance.
func WithLogger(logger *zerolog.Logger) Option {
	return func(h *HTTPClient) {
		h.logger = logger
	}
}
