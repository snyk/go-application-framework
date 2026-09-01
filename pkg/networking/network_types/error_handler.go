package networktypes

import (
	"context"
	"net/http"
)

type ErrorHandlerFunc func(err error, ctx context.Context) error

type MiddlewareFunc func(http.RoundTripper) http.RoundTripper
