// Package machine_workflow provides the workflows that enroll this device as a machine principal
// and check its credential.
package machine_workflow

import (
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	enrollWorkflowName = "machine enroll"
	statusWorkflowName = "machine status"
)

var (
	WORKFLOWID_MACHINE_ENROLL workflow.Identifier = workflow.NewWorkflowIdentifier(enrollWorkflowName)
	WORKFLOWID_MACHINE_STATUS workflow.Identifier = workflow.NewWorkflowIdentifier(statusWorkflowName)
)

// InitMachineWorkflows registers the machine workflows. Both are experimental.
func InitMachineWorkflows(engine workflow.Engine) error {
	enrollFlags := pflag.NewFlagSet(enrollWorkflowName, pflag.ExitOnError)
	_, err := engine.Register(
		WORKFLOWID_MACHINE_ENROLL,
		workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(enrollFlags)),
		enrollEntryPoint,
	)
	if err != nil {
		return err
	}

	statusFlags := pflag.NewFlagSet(statusWorkflowName, pflag.ExitOnError)
	_, err = engine.Register(
		WORKFLOWID_MACHINE_STATUS,
		workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(statusFlags)),
		statusEntryPoint,
	)
	return err
}
