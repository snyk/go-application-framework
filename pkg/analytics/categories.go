package analytics

import (
	"slices"
	"strings"
)

// ParseCliArgs categorizes command-line arguments into a structured slice.
//
// This function receives the entire os.Args slice (including the program name at index 0)
// and processes the arguments to determine the product, commands, and flags.
// It is designed to handle arguments in any order.
//
// The function performs the following actions:
//  1. It identifies the product based on the following rules:
//     - If the command is "test" and no other commands are present, the product is "oss" (open-source software).
//     - Otherwise, no product is explicitly identified.
//  2. It extracts known commands and whitelisted flags from the arguments. Flags after a double dash ("--") are ignored.
//  3. It constructs a slice containing the categorized arguments in the following order:
//     - [product] (if applicable)
//     - [command(s)]
//     - [flags] (without leading dashes)
//
// If no known commands or flags are found, the returned slice will be empty.
//
// Example:
//
//	args := []string{"cli", "scan", "--debug", "--"}
//	knownCommands := []string{"scan", "build"}
//	flagsAllowList := []string{"debug", "verbose"}
//	result := ParseCliArgs(args, knownCommands, flagsAllowList)
//	// result: ["scan", "debug"]
//
// Parameters:
//   - args: A slice of strings representing the entire os.Args.
//   - knownCommands: A slice of valid command names.
//   - flagsAllowList: A slice of valid flag names (without leading dashes).
//
// Returns:
//   - A slice of strings containing the categorized arguments.
func ParseCliArgs(args []string, knownCommands []string, flagsAllowList []string, knownProducts []string) []string {
	commands := []string{}
	flags := []string{}
	result := []string{}

	productFallback := "oss"

	// Separate parsing of commands and flags to ensure correct ordering in the category vector
	// regardless of how they are provided in the command line.
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			if arg == "--" {
				break
			}

			// Split the flag into key and potential value
			flagParts := strings.SplitN(arg, "=", 2)
			flagName := strings.TrimLeft(flagParts[0], "-")

			if slices.Contains(flagsAllowList, flagName) {
				flags = append(flags, flagName)
			}
		} else if slices.Contains(knownCommands, arg) {
			if len(commands) == 0 && arg == "test" {
				result = append(commands, productFallback)
			}

			commands = append(commands, arg)
		}
	}

	result = append(result, commands...)
	result = append(result, flags...)

	return result
}

var PRODUCTS = []string{"code", "iac", "container", "sbom"}
var KNOWN_COMMANDS = []string{"test", "code", "monitor", "iac", "rules", "describe", "sbom", "container", "debug"}
var ALLOWED_FLAGS = []string{
	"print-dep-paths",
	"print-deps",
	"max-depth",
	"policy-path",
	"project-name",
	"target-reference",
	"remote-repo-url",
	"exclude-base-image-vulns",
	"exclude-app-vulns",
	"dev",
	"advertise-subprojects-count",
	"project-tags",
	"all-projects",
	"all-sub-projects",
	"app-vulns",
	"code",
	"command",
	"commit-id",
	"config-dir",
	"criticality",
	"debug",
	"detection-depth",
	"docker",
	"driftignore",
	"dry-run",
	"exclude",
	"exclude-missing",
	"exclude-unmanaged",
	"experimental",
	"fail-fast",
	"fail-on",
	"fetch-tfstate-headers",
	"file",
	"filter",
	"from",
	"gradle-sub-project",
	"group-issues",
	"html",
	"html-file-output",
	"iac",
	"id",
	"ignore",
	"ignore-policy",
	"init-script",
	"insecure",
	"is-docker-user",
	"json",
	"kind",
	"loose",
	"maven-aggregate-project",
	"no-markdown",
	"org",
	"package-manager",
	"path",
	"policy",
	"project-id",
	"project-names",
	"prune-repeated-subdependencies",
	"quiet",
	"report",
	"sarif",
	"scan-all-unmanaged",
	"service",
	"severity-threshold",
	"show-vuln-paths",
	"show-vulnerable-paths",
	"strict",
	"strict-out-of-sync",
	"tags",
	"target-name",
	"test-dep-graph-docker-endpoint",
	"tf-lockfile",
	"tf-provider-version",
	"tfc-endpoint",
	"tfc-token",
	"to",
	"traverse-node-modules",
	"trust-policies",
	"unmanaged",
	"var-file",
	"vuln-endpoint",
	"yarn-workspaces",
}
