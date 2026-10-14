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

// Init registers a post-invoke hook that reports contributors for the
// captured entity, together with the middleware to capture the entities.
func Init(engine workflow.Engine) error {
	config_utils.AddFeatureFlagsToConfig(engine, flagMap)
	config, logger := engine.GetConfiguration(), engine.GetLogger()

	if config.GetBool(configEnableEntityContributorsPublish) {
		sink := &contributors.Sink{}
		hook := func(ctx context.Context, e workflow.Engine, _ workflow.InvokeOutput) {
			contributors.Report(ctx, e, sink)
		}
		middleware := contributor_capture.NewContributorCaptureMiddleware(config, sink, logger)

		engine.GetNetworkAccess().AddMiddleware(middleware)
		if err := workflow.AddPostInvokeHook(engine, hook); err != nil {
			logger.Debug().Err(err).Msg("contributors: failed to register post-invoke hook")
		}
	}

	return nil
}
