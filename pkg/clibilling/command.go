package clibilling

import (
	"context"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// FinishCommand waits for contributor billing ingest started during capture.
// Deprecated: billing no longer finalizes at CLI teardown; the post-invoke hook waits instead.
func FinishCommand(ctx context.Context, engine workflow.Engine, config configuration.Configuration, _ bool) bool {
	return WaitForPendingEmit(ctx, engine, config)
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
