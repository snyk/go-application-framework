package instrumentation

import (
	"strings"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func GetKnownCommandsAndFlags(engine workflow.Engine) ([]string, []string) {
	knownCommands := analytics.KNOWN_COMMANDS
	knownFlags := analytics.KNOWN_FLAGS

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
			knownFlags = append(knownFlags, flag.Name)
		})
	}

	return knownCommands, knownFlags
}
