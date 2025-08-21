package instrumentation

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

func GetKnownCommandsAndFlags(engine workflow.Engine) ([]string, []string) {
	knownCommands := KNOWN_COMMANDS
	knownFlags := known_flags

	workflowIDs := engine.GetWorkflows()
	for _, id := range workflowIDs {
		wfl, err := engine.GetWorkflow(id)
		if !err {
			continue
		}

		// add command to knownCommands
		currentCommandString := workflow.GetCommandFromWorkflowIdentifier(id)
		additionalKnownCommands := strings.Split(currentCommandString, " ")
		knownCommands = append(knownCommands, additionalKnownCommands...)

		// add flags to knownFlags
		flagset := workflow.FlagsetFromConfigurationOptions(wfl.GetConfigurationOptions())
		flagset.VisitAll(func(flag *pflag.Flag) {
			if !slices.Contains(knownFlags, flag.Name) {
				knownFlags = append(knownFlags, flag.Name)
			}
		})
	}

	return knownCommands, knownFlags
}

func DetermineStage(isCiEnvironment bool) string {
	if isCiEnvironment {
		return "cicd"
	}

	return "dev"
}

func AssembleUrnFromUUID(uuid string) string {
	urnPrefix := "urn:snyk:interaction"
	if strings.Contains(uuid, urnPrefix) {
		return uuid
	}
	return fmt.Sprintf("%s:%s", urnPrefix, uuid)
}
