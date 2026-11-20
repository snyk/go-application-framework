package profile

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// markerKey holds the name of the active named profile on a derived configuration.
// It deliberately avoids the snyk_ and internal_ prefixes so supported-prefix binding
// does not treat it as an environment key. The registry sets it explicitly with Set.
const markerKey = "gaf_config_profile_marker"

// IsProfile reports whether config belongs to a named (non-default) profile.
// The default profile has no marker.
func IsProfile(config configuration.Configuration) bool {
	return Name(config) != ""
}

// Name returns the named profile stored on config, or the empty string for the default profile
// or when config is nil.
func Name(config configuration.Configuration) string {
	if config == nil {
		return ""
	}
	return config.GetString(markerKey)
}

// SetMarker records that config is the named profile. It is used by the registry when loading
// a non-default profile, and by host enrichment callbacks that opt into the same marker.
func SetMarker(config configuration.Configuration, name string) {
	if config == nil || name == "" || name == DefaultName {
		return
	}
	config.Set(markerKey, name)
}
