// Package profile provides named configurations. Each non-default profile reads its values from its own file, so
// profiles do not share values. A Registry finds profiles by name.
package profile

import (
	"errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// DefaultName is the name of the default profile, whose configuration is the base configuration of the registry.
const DefaultName = "default"

// ErrNotFound is returned when a profile does not exist.
var ErrNotFound = errors.New("profile not found")

// ErrInvalidName is returned when a profile name is not allowed.
var ErrInvalidName = errors.New("invalid profile name")

// ErrCorrupt is returned when a profile file exists but is not a valid configuration file.
var ErrCorrupt = errors.New("profile file is not valid")

// Registry finds profiles by name.
type Registry interface {
	// Profile returns the profile with the given name, or ErrNotFound if it does not exist.
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
