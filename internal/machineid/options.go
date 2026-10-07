package machineid

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

// resolveOptions holds the configuration for a single Resolve call, built from ResolveOption values.
type resolveOptions struct {
	runtimeInfo func() runtimeinfo.RuntimeInfo
	logger      *zerolog.Logger
}

// ResolveOption configures optional behavior of Resolve.
type ResolveOption func(*resolveOptions)

// WithLogger sets the logger used to trace resolution decisions at Debug level, including errors
// that resolution otherwise swallows so a run can still produce a value. If unset, Resolve uses a
// no-op logger.
func WithLogger(logger *zerolog.Logger) ResolveOption {
	return func(o *resolveOptions) {
		o.logger = logger
	}
}

// WithRuntimeInfo identifies the consumer resolving the machine id, recorded as the writer field
// in the shared machine-id file so a machine carrying values written by several different
// products or versions is identifiable. get is called when the file is written rather than when
// Resolve is called, so runtime info set on the engine after it was created is still used. If
// unset, or if get returns nil, a generic framework identifier is recorded.
func WithRuntimeInfo(get func() runtimeinfo.RuntimeInfo) ResolveOption {
	return func(o *resolveOptions) {
		o.runtimeInfo = get
	}
}
