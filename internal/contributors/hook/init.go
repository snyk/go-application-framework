package hook

import (
	"context"

	"github.com/snyk/go-application-framework/internal/contributors"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
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

// Init registers the contributors feature flag, capture middleware, and a
// post-invoke hook that reports when the flag is on.
//
// The flag is not read during Init. Hosts such as the CLI select a configuration
// profile only after Init, so an eager read would resolve organization and
// feature flags with the default configuration's credentials. The hook reads
// the flag on the invocation's configuration instead, which is the selected
// profile when one is in use.
func Init(engine workflow.Engine) error {
	config_utils.AddFeatureFlagsToConfig(engine, flagMap)
	config, logger := engine.GetConfiguration(), engine.GetLogger()

	sink := &contributors.Sink{}
	hook := func(ctx context.Context, e workflow.Engine, _ workflow.InvokeOutput) {
		if !e.GetConfiguration().GetBool(configEnableEntityContributorsPublish) {
			return
		}
		contributors.Report(ctx, e, sink)
	}
	middleware := contributor_capture.NewContributorCaptureMiddleware(config, sink, logger)

	engine.GetNetworkAccess().AddMiddleware(middleware)
	if err := workflow.AddPostInvokeHook(engine, hook); err != nil {
		logger.Debug().Err(err).Msg("contributors: failed to register post-invoke hook")
	}

	return nil
}
