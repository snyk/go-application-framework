package machineid

import "github.com/rs/zerolog"

// resolveOptions holds the configuration for a single Resolve call, built from ResolveOption values.
type resolveOptions struct {
	legacyPath  string
	legacyParse func([]byte) (string, error)
	logger      *zerolog.Logger
}

// ResolveOption configures optional behavior of Resolve.
type ResolveOption func(*resolveOptions)

// WithLegacyDeviceIDFile opts in to reading a pre-existing legacy device-id file when no other
// source produces a value. parse extracts the identifier from the file's contents. Trailing
// whitespace, including a trailing newline, is then removed from the parsed value, since a
// device-id file written by an earlier product typically ends with one as a file-format artifact
// rather than part of the identifier. No other source is trimmed this way; this is parsing, not
// validation, and it does not imply the identifier has any defined format.
func WithLegacyDeviceIDFile(path string, parse func([]byte) (string, error)) ResolveOption {
	return func(o *resolveOptions) {
		o.legacyPath = path
		o.legacyParse = parse
	}
}

// WithLogger sets the logger used to trace resolution decisions at Debug level, including errors
// that resolution otherwise swallows so a run can still produce a value. If unset, Resolve uses a
// no-op logger.
func WithLogger(logger *zerolog.Logger) ResolveOption {
	return func(o *resolveOptions) {
		o.logger = logger
	}
}
