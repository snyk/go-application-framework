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
// Setup hooks are not applied here: they may read configuration (and thus the engine) and must
// run via ApplyNetworkAccessSetup only when the engine lock is not held.
func CreateNetworkAccess(base networking.NetworkAccess, config configuration.Configuration) networking.NetworkAccess {
	networkAccess := base.Clone()
	networkAccess.SetConfiguration(config)
	return networkAccess
}

// ApplyNetworkAccessSetup runs setup hooks registered on na for its current configuration.
// Call it after CreateNetworkAccess when the engine lock is not held. Hooks may resolve
// remote-backed configuration and must not run under the engine mutex.
func ApplyNetworkAccessSetup(na networking.NetworkAccess) {
	if setup, ok := na.(networking.NetworkAccessSetup); ok {
		setup.ApplySetupHooks()
	}
}
