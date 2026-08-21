package clibilling

import (
	"strings"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ConfigurationKeyCaptureEnabled opts the CLI into contributor billing capture.
const ConfigurationKeyCaptureEnabled = capture.ConfigurationKeyCaptureEnabled

// DefaultRepoPath returns the git root used for contributor collection at emit time.
func DefaultRepoPath(workingDirectory string) string {
	if strings.TrimSpace(workingDirectory) == "" {
		return "."
	}
	return workingDirectory
}

// ActiveCommand returns the in-flight CLI command used for contributor billing gating
// from analytics plus RAW_CMD_ARGS (analytics omits flags such as --report).
func ActiveCommand(engine workflow.Engine) string {
	if engine == nil {
		return ""
	}
	analyticsCommand := ""
	if analytics := engine.GetAnalytics(); analytics != nil {
		analyticsCommand = strings.TrimSpace(analytics.GetCommand())
	}
	config := engine.GetConfiguration()
	if config == nil {
		return analyticsCommand
	}
	return capture.ResolveBillableCommand(analyticsCommand, config.GetStringSlice(configuration.RAW_CMD_ARGS))
}

// EnsureCaptureSession lazily opens the command capture session when none is active.
func EnsureCaptureSession(engine workflow.Engine) *capture.Capture {
	if engine == nil {
		return nil
	}
	return capture.EnsureCaptureSessionForConfig(engine.GetConfiguration(), ActiveCommand(engine))
}

// RepoPathFromConfig returns the git root from the first INPUT_DIRECTORY entry, or ".".
func RepoPathFromConfig(config configuration.Configuration) string {
	if config == nil {
		return "."
	}
	dirs := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(dirs) > 0 {
		return DefaultRepoPath(dirs[0])
	}
	return "."
}
