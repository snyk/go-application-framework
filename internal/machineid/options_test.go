package machineid

import "time"

// withPaths replaces the shared file and Snyk Studio device-id locations, so tests stay off the
// real machine-wide paths.
func withPaths(shared, studio pathPair) ResolveOption {
	return func(o *resolveOptions) {
		o.shared = shared
		o.studio = studio
	}
}

// withClock replaces the clock the resolver uses to decide when to retry a failed lookup.
func withClock(now func() time.Time) ResolveOption {
	return func(o *resolveOptions) {
		o.now = now
	}
}
