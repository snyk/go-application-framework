package workflow

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

// CreateNetworkAccessFromEngine returns the network access that uses the given configuration for its credentials and host.
// The engine's own network access is returned for the engine's configuration, otherwise a clone bound to the given one.
// The result may be the engine's shared instance, so callers must only read from it, never mutate it.
func CreateNetworkAccessFromEngine(engine Engine, config configuration.Configuration) networking.NetworkAccess {
	if config == engine.GetConfiguration() {
		return engine.GetNetworkAccess()
	}

	return CreateNetworkAccess(engine.GetNetworkAccess(), config)
}

// CreateNetworkAccess always returns a fresh clone of base bound to the given configuration.
// It does not call engine accessors, so it is safe to use while the engine lock is held.
func CreateNetworkAccess(base networking.NetworkAccess, config configuration.Configuration) networking.NetworkAccess {
	networkAccess := base.Clone()
	networkAccess.SetConfiguration(config)
	return networkAccess
}
