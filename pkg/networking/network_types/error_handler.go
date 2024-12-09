package networktypes

import "context"

type ErrorHandlerFunc func(err error, ctx context.Context) error
