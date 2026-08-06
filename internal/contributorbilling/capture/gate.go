package capture

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// IsBillableCommand reports whether the CLI command is in scope for contributor billing.
func IsBillableCommand(command string) bool {
	command = strings.TrimSpace(strings.ToLower(command))
	if command == "" {
		return false
	}
	if command == "monitor" || strings.HasPrefix(command, "monitor ") {
		return true
	}
	if !strings.Contains(command, "--report") {
		return false
	}
	return strings.HasPrefix(command, "iac test") || strings.HasPrefix(command, "code test")
}

// CommandNameFromRawArgs derives a billing command label from legacy CLI argv.
func CommandNameFromRawArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	if len(args) >= 2 && (args[0] == "iac" || args[0] == "code") && args[1] == "test" {
		name := args[0] + " " + args[1]
		for _, arg := range args[2:] {
			if arg == "--report" {
				return name + " --report"
			}
		}
		return name
	}
	return args[0]
}

// CaptureEnabledForBillableHTTP reports whether capture may run for the active command.
func CaptureEnabledForBillableHTTP(config configuration.Configuration, command string) bool {
	if config == nil || !config.GetBool(ConfigurationKeyCaptureEnabled) {
		return false
	}
	return IsBillableCommand(command)
}

// EnsureCaptureSessionForConfig lazily opens the command capture session when eligible.
func EnsureCaptureSessionForConfig(config configuration.Configuration, command string) *Capture {
	if !CaptureEnabledForBillableHTTP(config, command) {
		return nil
	}
	return EnsureCommandSession(repoPathFromConfig(config))
}

func repoPathFromConfig(config configuration.Configuration) string {
	if config == nil {
		return "."
	}
	dirs := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(dirs) > 0 {
		repoPath := strings.TrimSpace(dirs[0])
		if repoPath != "" {
			return repoPath
		}
	}
	return "."
}
