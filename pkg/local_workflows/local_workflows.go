package localworkflows

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initializes all local workflows
// localworkflows are initialized when create a new workflow engine via app.CreateAppEngine()
func Init(engine workflow.Engine) error {
	workflows := []workflow.WorkflowRegisterer{
		OpenSourceDepGraph,
		Output,
		WhoAmI,
	}
	// Only register if the OAuth flow is ready.
	if engine.GetConfiguration().GetBool(configuration.FF_OAUTH_AUTH_FLOW_ENABLED) {
		workflows = append(workflows, Auth)
	}

	for _, w := range workflows {
		if err := workflow.Register(w, engine); err != nil {
			return err
		}
	}

	return nil
}
