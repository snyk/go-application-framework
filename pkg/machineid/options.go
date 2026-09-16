package machineid

// resolveOptions holds the configuration for a single Resolve call, built from ResolveOption values.
type resolveOptions struct {
	legacyPath  string
	legacyParse func([]byte) (string, error)
}

// ResolveOption configures optional behavior of Resolve.
type ResolveOption func(*resolveOptions)

// WithLegacyDeviceIdFile opts in to reading a pre-existing legacy device-id file when no other
// source produces a value. parse extracts the identifier from the file's contents. Trailing
// whitespace, including a trailing newline, is then removed from the parsed value, since a
// device-id file written by an earlier product typically ends with one as a file-format artifact
// rather than part of the identifier. No other source is trimmed this way; this is parsing, not
// validation, and it does not imply the identifier has any defined format.
func WithLegacyDeviceIdFile(path string, parse func([]byte) (string, error)) ResolveOption {
	return func(o *resolveOptions) {
		o.legacyPath = path
		o.legacyParse = parse
	}
}
