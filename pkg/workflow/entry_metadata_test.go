package workflow_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Engine_RegisteredEntryCarriesMetadata(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	id := workflow.NewWorkflowIdentifier("metadata acceptance")
	flags := pflag.NewFlagSet("metadata", pflag.ContinueOnError)

	entry, err := engine.Register(id, workflow.ConfigurationOptionsFromFlagset(flags), noopRegistrationCallback)
	require.NoError(t, err)

	withMetadata, ok := entry.(workflow.EntryWithMetadata)
	require.True(t, ok, "entries returned by Register must support metadata")
	require.NoError(t, withMetadata.SetMetadata("count", 3))
	require.NoError(t, withMetadata.SetMetadata("owner", "team-a"))

	found, ok := engine.GetWorkflow(id)
	require.True(t, ok)
	stored, ok := found.(workflow.EntryWithMetadata)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"count": 3, "owner": "team-a"}, stored.Metadata())

	require.Error(t, stored.SetMetadata("owner", "team-b"), "a metadata value must not change once it is set")
	assert.Equal(t, "team-a", stored.Metadata()["owner"])
}
