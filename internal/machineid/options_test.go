package machineid

// withPaths replaces the shared file and Snyk Studio device-id locations, so tests stay off the
// real machine-wide paths.
func withPaths(shared, studio pathPair) ResolveOption {
	return func(o *resolveOptions) {
		o.shared = shared
		o.studio = studio
	}
}
