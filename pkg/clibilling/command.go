package clibilling

import (
	"context"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// FinishCommand closes the active capture session and emits captured billing on success.
// Called from CLI teardown after all top-level invocations complete.
func FinishCommand(ctx context.Context, engine workflow.Engine, config configuration.Configuration, success bool) bool {
	return finalizeContributorBilling(ctx, engine, config, success)
}

func captureEnabled(config configuration.Configuration) bool {
	return config != nil && config.GetBool(ConfigurationKeyCaptureEnabled)
}

// IsBillableCommand reports whether the CLI command is in scope for contributor billing.
func IsBillableCommand(command string) bool {
	return capture.IsBillableCommand(command)
}

// CaptureEnabledForConfig reports whether contributor billing capture is enabled for config.
func CaptureEnabledForConfig(config configuration.Configuration) bool {
	return captureEnabled(config)
}
