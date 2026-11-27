package lifecycle_workflow_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	lifecycle "github.com/snyk/go-application-framework/pkg/local_workflows/lifecycle_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Acceptance: install and uninstall are experimental, so the CLI requires --experimental to run them.
func Test_InstallAndUninstall_AreExperimental(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, lifecycle.InitLifecycleWorkflows(engine))
	require.NoError(t, engine.Init())

	for _, id := range []workflow.Identifier{lifecycle.WORKFLOWID_INSTALL, lifecycle.WORKFLOWID_UNINSTALL} {
		entry, ok := engine.GetWorkflow(id)
		require.True(t, ok, "workflow %s should be registered", id.String())
		flagset := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
		require.NotNil(t, flagset, "workflow %s should have a flagset", id.String())
		assert.True(t, config_utils.IsExperimental(flagset), "workflow %s should be experimental", id.String())
		experimentalFlag := flagset.Lookup(configuration.FLAG_EXPERIMENTAL)
		require.NotNil(t, experimentalFlag)
		assert.Equal(t, "false", experimentalFlag.DefValue, "the experimental flag of workflow %s should default to off", id.String())
	}
}
