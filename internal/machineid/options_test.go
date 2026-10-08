package machineid

import "time"

func withPaths(shared, studio pathPair) ResolveOption {
	return func(o *resolveOptions) {
		o.shared = shared
		o.studio = studio
	}
}

func withClock(now func() time.Time) ResolveOption {
	return func(o *resolveOptions) {
		o.now = now
	}
}
