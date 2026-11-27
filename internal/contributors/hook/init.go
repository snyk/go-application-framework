package hook

import (
	"context"

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
// contributors feature flag is on for that configuration. The flag is not read during Init:
// hosts such as the CLI select a profile afterwards, and ApplyNetworkAccessSetup runs these
// hooks with the configuration that will make the requests.
//
// The feature-flag gateway already caches per organization; this type does not add another
// cache, so multi-org hosts (IDE/MCP) keep the correct per-org decision.
type activator struct {
	sink   *contributors.Sink
	logger *zerolog.Logger
}

func (a *activator) setup(na networking.NetworkAccess, cfg configuration.Configuration) {
	enabled, err := cfg.GetBoolWithError(configEnableEntityContributorsPublish)
	if err != nil {
		a.logger.Debug().Err(err).Msg("contributors: feature flag lookup failed; capture not enabled")
		return
	}
	if !enabled {
		return
	}
	na.AddMiddleware(contributor_capture.NewContributorCaptureMiddleware(cfg, a.sink, a.logger))
}

// Init registers the contributors feature flag and a post-invoke reporter. Capture middleware
// is installed later, when ApplyNetworkAccessSetup runs setup hooks for a configuration, so the
// flag is resolved with that configuration's credentials rather than the default profile's.
func Init(engine workflow.Engine) error {
	config_utils.AddFeatureFlagsToConfig(engine, flagMap)
	logger := engine.GetLogger()

	sink := &contributors.Sink{}
	act := &activator{sink: sink, logger: logger}

	if setup, ok := engine.GetNetworkAccess().(networking.NetworkAccessSetup); ok {
		setup.AddSetupHook(act.setup)
	} else {
		logger.Debug().Msg("contributors: network access does not support setup hooks")
	}

	hook := func(ctx context.Context, e workflow.Engine, _ workflow.InvokeOutput) {
		cfg := e.GetConfiguration()
		enabled, err := cfg.GetBoolWithError(configEnableEntityContributorsPublish)
		if err != nil || !enabled {
			return
		}
		contributors.Report(ctx, e, sink)
	}
	if err := workflow.AddPostInvokeHook(engine, hook); err != nil {
		logger.Debug().Err(err).Msg("contributors: failed to register post-invoke hook")
	}

	return nil
}
