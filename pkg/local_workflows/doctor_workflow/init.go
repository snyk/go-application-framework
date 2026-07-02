package doctor_workflow

import (
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	doctorWorkflowName = "doctor"

	inputFlag       = "input"
	noLiveCheckFlag = "no-live-check"
	jsonFlag        = "json"
)

var WORKFLOWID_DOCTOR workflow.Identifier = workflow.NewWorkflowIdentifier(doctorWorkflowName)

func InitDoctorWorkflow(engine workflow.Engine) error {
	flags := pflag.NewFlagSet(doctorWorkflowName, pflag.ExitOnError)
	flags.String(inputFlag, "", "Path to a Snyk CLI debug log file.")
	flags.Bool(noLiveCheckFlag, false, "Skip live authentication and connectivity checks.")
	flags.Bool(jsonFlag, false, "Output the diagnostic report as JSON.")

	_, err := engine.Register(
		WORKFLOWID_DOCTOR,
		workflow.ConfigurationOptionsFromFlagset(flags),
		doctorEntryPoint,
	)
	return err
}
