package workflow

// FlagValidator is an optional interface that workflows can
// implement to validate raw command-line arguments
type FlagValidator interface {
	ValidatePreParse(rawArgs []string) error
}

// ValidatePreParse validates raw command-line arguments for a workflow before flag parsing.
func ValidatePreParse(engine Engine, command string, rawArgs []string) error {
	workflowId := NewWorkflowIdentifier(command)

	workflow, ok := engine.GetWorkflow(workflowId)
	if !ok {
		return nil
	}

	configOpts := workflow.GetConfigurationOptions()
	validator, ok := configOpts.(FlagValidator)
	if !ok {
		return nil
	}

	return validator.ValidatePreParse(rawArgs)
}
