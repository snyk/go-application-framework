package hook

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

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
// during Init: hosts such as the CLI select a profile afterwards, and CreateNetworkAccess runs
// setup hooks with the configuration that will make the requests.
type activator struct {
	sink   *contributors.Sink
	logger *zerolog.Logger

	mu         sync.Mutex
	enabled    map[string]bool
	resolving  bool // re-entrancy guard: GetBool may CreateNetworkAccess while resolving
}

func (a *activator) setup(na networking.NetworkAccess, cfg configuration.Configuration) {
	key := decisiveConfigKey(cfg)

	a.mu.Lock()
	if a.resolving {
		a.mu.Unlock()
		return
	}
	enabled, known := a.enabled[key]
	if !known {
		a.resolving = true
		a.mu.Unlock()
		enabled = cfg.GetBool(configEnableEntityContributorsPublish)
		a.mu.Lock()
		a.resolving = false
		a.enabled[key] = enabled
	}
	a.mu.Unlock()

	if !enabled {
		return
	}
	na.AddMiddleware(contributor_capture.NewContributorCaptureMiddleware(cfg, a.sink, a.logger))
}

func decisiveConfigKey(cfg configuration.Configuration) string {
	// Credentials + API host identify who the flag must be resolved for. Do not read
	// ORGANIZATION here: that would trigger further remote lookups before the flag decision.
	return cfg.GetString(configuration.API_URL) + "\x00" +
		cfg.GetString(configuration.AUTHENTICATION_TOKEN) + "\x00" +
		cfg.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
}

// Init registers the contributors feature flag and a post-invoke reporter. Capture middleware
// is installed later, when CreateNetworkAccess applies setup hooks for a configuration, so the
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
		act.mu.Lock()
		enabled, known := act.enabled[key]
		act.mu.Unlock()
		if !known {
			enabled = cfg.GetBool(configEnableEntityContributorsPublish)
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
