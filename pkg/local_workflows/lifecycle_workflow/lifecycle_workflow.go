// Package lifecycle_workflow registers the install and uninstall workflows. They run the steps that extensions provide for
// a lifecycle: the workflows labeled with that lifecycle. GAF installs nothing itself. Both workflows are experimental.
package lifecycle_workflow

import (
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

const (
	installWorkflowName   = "install"
	uninstallWorkflowName = "uninstall"
)

// WORKFLOWID_INSTALL and WORKFLOWID_UNINSTALL identify the workflows that run the install and uninstall steps.
var (
	WORKFLOWID_INSTALL   workflow.Identifier = workflow.NewWorkflowIdentifier(installWorkflowName)
	WORKFLOWID_UNINSTALL workflow.Identifier = workflow.NewWorkflowIdentifier(uninstallWorkflowName)
)

// InitLifecycleWorkflows registers the install and uninstall workflows with the engine. Both are experimental, so the
// CLI requires --experimental to run them.
func InitLifecycleWorkflows(engine workflow.Engine) error {
	_, err := engine.Register(
		WORKFLOWID_INSTALL,
		workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(pflag.NewFlagSet(installWorkflowName, pflag.ExitOnError))),
		lifecycleEntryPoint(catalog.Install),
	)
	if err != nil {
		return err
	}

	_, err = engine.Register(
		WORKFLOWID_UNINSTALL,
		workflow.ConfigurationOptionsFromFlagset(config_utils.MarkAsExperimental(pflag.NewFlagSet(uninstallWorkflowName, pflag.ExitOnError))),
		lifecycleEntryPoint(catalog.Uninstall),
	)
	return err
}

// lifecycleEntryPoint returns the callback that runs the steps of a lifecycle. It returns nil when no step fails, and
// otherwise one error that lists the failed steps. The output data of the steps is dropped.
func lifecycleEntryPoint(lifecycle catalog.Lifecycle) workflow.Callback {
	return func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		failures := catalog.RunLifecycle(ic, lifecycle)
		if len(failures) == 0 {
			return nil, nil
		}
		err := installOrUninstallFailedError(failureDetail(ic.GetConfiguration(), failures), failureCauses(failures))
		return nil, err
	}
}
