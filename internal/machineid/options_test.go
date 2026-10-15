package machineid

// withPaths replaces the shared file and Snyk Studio device-id locations, so tests stay off the
// real machine-wide paths.
func withPaths(shared, studio pathPair) ResolveOption {
	return func(o *resolveOptions) {
		o.shared = shared
		o.studio = studio
	}
}

// withHardware replaces the hardware serial and hostname sources, so tests do not depend on the
// machine they run on.
func withHardware(serial, hostname string) ResolveOption {
	return func(o *resolveOptions) {
		o.serialNumber = func() (string, error) { return serial, nil }
		o.hostname = func() (string, error) { return hostname, nil }
	}
}
