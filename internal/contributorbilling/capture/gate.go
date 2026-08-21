package capture

import (
	"os"
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
	if command == "aibom --upload" || (strings.HasPrefix(command, "aibom ") && strings.Contains(command, "--upload")) {
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
			if arg == "--report" || strings.HasPrefix(arg, "--report=") {
				return name + " --report"
			}
		}
		return name
	}
	if len(args) >= 1 && args[0] == "aibom" {
		for _, arg := range args[1:] {
			if arg == "--upload" || strings.HasPrefix(arg, "--upload=") {
				return "aibom --upload"
			}
		}
	}
	return args[0]
}

// ResolveBillableCommand picks the command label used for billing gating.
// cliv2 analytics SetCommand omits flags (e.g. "iac test"). Prefer argv-derived
// labels from configured RAW_CMD_ARGS, then os.Args (main workflow never sets RAW_CMD_ARGS).
func ResolveBillableCommand(analyticsCommand string, rawArgs []string) string {
	for _, args := range [][]string{rawArgs, processArgs()} {
		fromArgs := CommandNameFromRawArgs(args)
		if IsBillableCommand(fromArgs) {
			return fromArgs
		}
	}
	analyticsCommand = strings.TrimSpace(analyticsCommand)
	if IsBillableCommand(analyticsCommand) {
		return analyticsCommand
	}
	if analyticsCommand != "" {
		return analyticsCommand
	}
	return CommandNameFromRawArgs(rawArgs)
}

func processArgs() []string {
	if len(os.Args) > 1 {
		return os.Args[1:]
	}
	return nil
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
	return ensureCommandSessionWithConfig(repoPathFromConfig(config), config)
}

func ensureCommandSessionWithConfig(repoPath string, config configuration.Configuration) *Capture {
	commandSession.mu.Lock()
	defer commandSession.mu.Unlock()

	if commandSession.sealed && commandSession.capture == nil {
		return nil
	}
	if commandSession.capture != nil {
		return commandSession.capture
	}

	bag := NewCapture()
	commandSession.capture = bag
	commandSession.repoPath = repoPath
	commandSession.captureConfig = config
	return bag
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
