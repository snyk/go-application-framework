// Package lifecycle_workflow registers the install and uninstall workflows. They run the steps that extensions provide:
// the workflows labeled with that lifecycle. GAF installs nothing itself.
package lifecycle_workflow

import (
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

const (
	installWorkflowName   = "install"
	uninstallWorkflowName = "uninstall"
)

var (
	WORKFLOWID_INSTALL   workflow.Identifier = workflow.NewWorkflowIdentifier(installWorkflowName)
	WORKFLOWID_UNINSTALL workflow.Identifier = workflow.NewWorkflowIdentifier(uninstallWorkflowName)
)

func InitLifecycleWorkflows(engine workflow.Engine) error {
	_, err := engine.Register(
		WORKFLOWID_INSTALL,
		workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet(installWorkflowName, pflag.ExitOnError)),
		lifecycleEntryPoint(catalog.Install),
	)
	if err != nil {
		return err
	}

	_, err = engine.Register(
		WORKFLOWID_UNINSTALL,
		workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet(uninstallWorkflowName, pflag.ExitOnError)),
		lifecycleEntryPoint(catalog.Uninstall),
	)
	return err
}

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
