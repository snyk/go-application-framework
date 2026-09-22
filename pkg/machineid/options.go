package machineid

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

// resolveOptions holds the configuration for a single Resolve call, built from ResolveOption values.
type resolveOptions struct {
	runtimeInfo      runtimeinfo.RuntimeInfo
	logger           *zerolog.Logger
	hardwareIdentity bool
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
// products or versions is identifiable. If unset, a generic framework identifier is recorded.
func WithRuntimeInfo(ri runtimeinfo.RuntimeInfo) ResolveOption {
	return func(o *resolveOptions) {
		o.runtimeInfo = ri
	}
}

// WithHardwareIdentity opts into two resolution sources the default chain deliberately omits: the
// machine's hardware serial number, tried immediately after an explicitly supplied value, and its
// hostname, tried immediately before a fresh id is minted. It exists for the one caller responsible
// for creating this machine's identity in the first place — a machine-provisioning installer — not
// for ordinary CLI, IDE, or MCP consumers, which must keep resolving through the unchanged default
// chain: an unprivileged component that resolved a hostname where a privileged installer could have
// resolved a hardware serial would mint a second, divergent identity for the same machine.
//
// The caller MUST invoke resolution before dropping any elevated privilege it holds. On Linux,
// reading the hardware serial number requires root; resolving after dropping to an unprivileged
// user silently degrades every machine to the hostname source, with no error, because this package
// has no way to detect or enforce the caller's privilege-drop sequencing.
func WithHardwareIdentity() ResolveOption {
	return func(o *resolveOptions) {
		o.hardwareIdentity = true
	}
}
