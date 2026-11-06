package localworkflows_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/instrumentation"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	lifecycle "github.com/snyk/go-application-framework/pkg/local_workflows/lifecycle_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Init_RegistersInstallAndUninstallWorkflows(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, localworkflows.Init(engine))
	require.NoError(t, engine.Init())

	_, ok := engine.GetWorkflow(lifecycle.WORKFLOWID_INSTALL)
	assert.True(t, ok, "install workflow is not registered by localworkflows.Init")
	_, ok = engine.GetWorkflow(lifecycle.WORKFLOWID_UNINSTALL)
	assert.True(t, ok, "uninstall workflow is not registered by localworkflows.Init")

	assert.Equal(t, []string{"install"}, instrumentation.DetermineCategory([]string{"snyk", "install"}, engine))
	assert.Equal(t, []string{"uninstall"}, instrumentation.DetermineCategory([]string{"snyk", "uninstall"}, engine))
}
