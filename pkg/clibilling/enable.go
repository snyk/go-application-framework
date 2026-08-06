package clibilling

import "github.com/snyk/go-application-framework/pkg/workflow"

// EnableIfConfigured registers contributor billing post-invoke hooks on the engine.
// Must be called before Init.
func EnableIfConfigured(engine workflow.Engine) workflow.Engine {
	if err := engine.AddPostInvokeHook(ContributorBillingPostInvokeHook); err != nil {
		engine.GetLogger().Warn().Err(err).Msg("failed to register contributor billing post-invoke hook")
	}
	return engine
}
