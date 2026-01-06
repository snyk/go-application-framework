package instrumentation

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/utils/target"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	FilesystemTargetId   = target.FilesystemTargetId
	AutoDetectedTargetId = target.AutoDetectedTargetId
)

type TargetIdType = target.TargetIdType
type TargetIdOptions = target.TargetIdOptions

var WithConfiguredRepository = target.WithConfiguredRepository

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

// GetTargetId returns the target ID for the given path
// Deprecated: Use target.GetTargetId instead.
func GetTargetId(path string, idType TargetIdType, options ...TargetIdOptions) (string, error) {
	return target.GetTargetId(path, idType, options...)
}
