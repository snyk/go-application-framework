package hook

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	featureFlagEnableEntityContributorsPublish = "enable-entity-contributors-publish"
	configEnableEntityContributorsPublish      = "internal_snyk_contributors_enabled"
)

var flagMap = map[string]string{
	configEnableEntityContributorsPublish: featureFlagEnableEntityContributorsPublish,
}

// activator installs capture middleware on network stacks bound to a configuration when the
// contributors feature flag is on for that configuration's credentials. The flag is not read
// during Init: hosts such as the CLI select a profile afterwards, and ApplyNetworkAccessSetup
// runs these hooks with the configuration that will make the requests.
type activator struct {
	sink   *contributors.Sink
	logger *zerolog.Logger

	mu      sync.Mutex
	enabled map[string]bool // successful resolutions only; failures are retried
	sf      singleflight.Group
}

func (a *activator) setup(na networking.NetworkAccess, cfg configuration.Configuration) {
	key := decisiveConfigKey(cfg)

	enabled, ok := a.lookup(key)
	if !ok {
		var err error
		enabled, err = a.resolve(key, cfg)
		if err != nil {
			a.logger.Debug().Err(err).Msg("contributors: feature flag lookup failed; capture not enabled")
			return
		}
	}

	if !enabled {
		return
	}
	na.AddMiddleware(contributor_capture.NewContributorCaptureMiddleware(cfg, a.sink, a.logger))
}

func (a *activator) lookup(key string) (enabled bool, known bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	enabled, known = a.enabled[key]
	return enabled, known
}

func (a *activator) resolve(key string, cfg configuration.Configuration) (bool, error) {
	v, err, _ := a.sf.Do(key, func() (any, error) {
		if enabled, known := a.lookup(key); known {
			return enabled, nil
		}
		enabled, err := cfg.GetBoolWithError(configEnableEntityContributorsPublish)
		if err != nil {
			return false, err
		}
		a.mu.Lock()
		a.enabled[key] = enabled
		a.mu.Unlock()
		return enabled, nil
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func decisiveConfigKey(cfg configuration.Configuration) string {
	// Credentials + API host identify who the flag must be resolved for. Do not read
	// ORGANIZATION here: that would trigger further remote lookups before the flag decision.
	return cfg.GetString(configuration.API_URL) + "\x00" +
		cfg.GetString(configuration.AUTHENTICATION_TOKEN) + "\x00" +
		cfg.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
}

// Init registers the contributors feature flag and a post-invoke reporter. Capture middleware
// is installed later, when ApplyNetworkAccessSetup runs setup hooks for a configuration, so the
// flag is resolved with that configuration's credentials rather than the default profile's.
func Init(engine workflow.Engine) error {
	config_utils.AddFeatureFlagsToConfig(engine, flagMap)
	logger := engine.GetLogger()

	sink := &contributors.Sink{}
	act := &activator{
		sink:    sink,
		logger:  logger,
		enabled: make(map[string]bool),
	}

	if setup, ok := engine.GetNetworkAccess().(networking.NetworkAccessSetup); ok {
		setup.AddSetupHook(act.setup)
	} else {
		logger.Debug().Msg("contributors: network access does not support setup hooks")
	}

	hook := func(ctx context.Context, e workflow.Engine, _ workflow.InvokeOutput) {
		cfg := e.GetConfiguration()
		key := decisiveConfigKey(cfg)
		enabled, known := act.lookup(key)
		if !known {
			var err error
			enabled, err = act.resolve(key, cfg)
			if err != nil {
				return
			}
		}
		if !enabled {
			return
		}
		contributors.Report(ctx, e, sink)
	}
	if err := workflow.AddPostInvokeHook(engine, hook); err != nil {
		logger.Debug().Err(err).Msg("contributors: failed to register post-invoke hook")
	}

	return nil
}
