package catalog_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

func noopCallback(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
	return nil, nil
}

func configOptions() workflow.ConfigurationOptions {
	return workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("catalog", pflag.ContinueOnError))
}

func metadataOf(t *testing.T, entry workflow.Entry) map[string]any {
	t.Helper()
	withMetadata, ok := entry.(workflow.EntryWithMetadata)
	require.True(t, ok, "entry must support metadata")
	return withMetadata.Metadata()
}

// Acceptance: a workflow registered with the lifecycle option is labeled, and the entry returned is the registered one.
func Test_Register_WithLifecycle_LabelsRegisteredWorkflow(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	id := workflow.NewWorkflowIdentifier("catalog install")

	entry, err := catalog.Register(engine, id, configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
	require.NoError(t, err)

	found, ok := engine.GetWorkflow(id)
	require.True(t, ok)
	assert.Same(t, entry, found)
	assert.Equal(t, map[string]any{"label:lifecycle": "install"}, metadataOf(t, found))
}

// Acceptance: a workflow registered from inside another workflow, through the engine its callback receives, is labeled.
func Test_Register_InsideWorkflow_LabelsNestedWorkflow(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	outerID := workflow.NewWorkflowIdentifier("catalog outer")
	nestedID := workflow.NewWorkflowIdentifier("catalog nested")

	_, err := engine.Register(outerID, configOptions(), func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		_, registerErr := catalog.Register(ic.GetEngine(), nestedID, configOptions(), noopCallback, catalog.WithLifecycle(catalog.Uninstall))
		return nil, registerErr
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	_, err = engine.Invoke(outerID)
	require.NoError(t, err)

	found, ok := engine.GetWorkflow(nestedID)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"label:lifecycle": "uninstall"}, metadataOf(t, found))
}

// Acceptance: when engine.Register fails, the error is returned with a nil entry and nothing stays registered.
func Test_Register_EngineFailure_ReturnsNilEntryAndError(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	id := workflow.NewWorkflowIdentifier("catalog broken")

	entry, err := catalog.Register(engine, id, configOptions(), nil, catalog.WithLifecycle(catalog.Install))
	require.Error(t, err)
	assert.Nil(t, entry)

	_, ok := engine.GetWorkflow(id)
	assert.False(t, ok)
}

// Acceptance: the query returns only the IDs of the workflows labeled lifecycle=install, sorted, both on the engine and
// on the engine a workflow callback receives.
func Test_FindByLifecycle_ReturnsSortedInstallWorkflows(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	zeta := workflow.NewWorkflowIdentifier("catalog zeta")
	alpha := workflow.NewWorkflowIdentifier("catalog alpha")
	removal := workflow.NewWorkflowIdentifier("catalog removal")
	plain := workflow.NewWorkflowIdentifier("catalog plain")
	lister := workflow.NewWorkflowIdentifier("catalog lister")

	register := func(id workflow.Identifier, opts ...catalog.RegisterOption) {
		_, err := catalog.Register(engine, id, configOptions(), noopCallback, opts...)
		require.NoError(t, err)
	}
	register(zeta, catalog.WithLifecycle(catalog.Install))
	register(alpha, catalog.WithLifecycle(catalog.Install))
	register(removal, catalog.WithLifecycle(catalog.Uninstall))
	register(plain)

	assert.Equal(t, []string{alpha.String(), zeta.String()}, idStrings(catalog.FindByLifecycle(engine, catalog.Install)))

	var fromWorkflow []string
	_, err := engine.Register(lister, configOptions(), func(ic workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		fromWorkflow = idStrings(catalog.FindByLifecycle(ic.GetEngine(), catalog.Install))
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, engine.Init())
	_, err = engine.Invoke(lister)
	require.NoError(t, err)

	assert.Equal(t, []string{alpha.String(), zeta.String()}, fromWorkflow)
}

func idStrings(ids []workflow.Identifier) []string {
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		result = append(result, id.String())
	}
	return result
}
