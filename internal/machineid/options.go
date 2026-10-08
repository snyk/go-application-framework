package machineid

import (
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

// resolveOptions holds the configuration for a single Resolve call, built from ResolveOption values.
type resolveOptions struct {
	runtimeInfo func() runtimeinfo.RuntimeInfo
	logger      *zerolog.Logger
	shared      pathPair
	studio      pathPair
	now         func() time.Time
}

// ResolveOption configures optional behavior of Resolve.
type ResolveOption func(*resolveOptions)

func WithLogger(logger *zerolog.Logger) ResolveOption {
	return func(o *resolveOptions) {
		o.logger = logger
	}
}

// WithRuntimeInfo names the consumer recorded as the shared file writer; get is called at write time.
func WithRuntimeInfo(get func() runtimeinfo.RuntimeInfo) ResolveOption {
	return func(o *resolveOptions) {
		o.runtimeInfo = get
	}
}
