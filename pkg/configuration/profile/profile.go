// Package profile provides named configurations. Each non-default profile reads its values from its own file, so
// profiles do not share values. A Registry finds profiles by name.
package profile

import (
	"errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// DefaultName is the name of the default profile, whose configuration is the base configuration of the registry.
const DefaultName = "default"

// ConfigKey is the configuration key that holds the name of the profile to use. An empty value, or "default", selects
// the default profile. The key is read from any source that the configuration of the application reads. For example,
// a configuration with automatic environment variables enabled, as configuration.New creates, reads the unprefixed
// environment variable CONFIG_PROFILE.
const ConfigKey = "config_profile"

// DirKey is the configuration key of the directory that directly holds the profile files, one <name>.json file per
// profile. The directory must be absolute. An application sets a default for it. Without a value, selecting a profile
// other than the default one fails with an error, see workflow.GetProfileRegistry. Like ConfigKey, the key is read
// from any source that the configuration reads, for example the unprefixed environment variable CONFIG_PROFILE_DIR
// with automatic environment variables enabled.
const DirKey = "config_profile_dir"

// ErrNotFound is returned when a profile does not exist.
//
// Deprecated: a profile without a file is an empty profile, nothing returns this error any more.
var ErrNotFound = errors.New("profile not found")

// Registry finds profiles by name.
type Registry interface {
	// Profile returns the profile with the given name. A profile without a file is empty, and reading it creates no
	// file: the file is created by the first persisted write. Errors are error-catalog errors: SNYK-CLI-0034 for an
	// invalid name, SNYK-CLI-0035 for a file that cannot be used, SNYK-CLI-0036 for a directory that cannot be used.
	Profile(name string) (Profile, error)
}

// Profile is one named profile.
type Profile interface {
	// Name is the profile's name.
	Name() string
	// Configuration holds the profile's values. The same instance is returned on every call.
	Configuration() configuration.Configuration
}

type profileImpl struct {
	name   string
	config configuration.Configuration
}

func (p *profileImpl) Name() string                               { return p.name }
func (p *profileImpl) Configuration() configuration.Configuration { return p.config }
