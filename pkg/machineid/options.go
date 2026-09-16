package machineid

// resolveOptions holds the configuration for a single Resolve call, built from ResolveOption values.
type resolveOptions struct {
	legacyPath  string
	legacyParse func([]byte) (string, error)
}

// ResolveOption configures optional behavior of Resolve.
type ResolveOption func(*resolveOptions)

// WithLegacyDeviceIdFile opts in to reading a pre-existing legacy device-id file when no other
// source produces a value. parse extracts the identifier from the file's contents.
func WithLegacyDeviceIdFile(path string, parse func([]byte) (string, error)) ResolveOption {
	return func(o *resolveOptions) {
		o.legacyPath = path
		o.legacyParse = parse
	}
}
