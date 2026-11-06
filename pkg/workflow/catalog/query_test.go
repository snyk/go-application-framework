package catalog_test

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

func labeledEntry(ctrl *gomock.Controller, metadata map[string]any) metadataEntry {
	entry := newMetadataEntry(ctrl)
	entry.MockEntryWithMetadata.EXPECT().Metadata().Return(metadata)
	return entry
}

func Test_FindByLifecycle_SkipsEntriesWithoutMatchingLabel(t *testing.T) {
	ctrl := gomock.NewController(t)
	plainID := workflow.NewWorkflowIdentifier("unit plain")
	installID := workflow.NewWorkflowIdentifier("unit install")
	uninstallID := workflow.NewWorkflowIdentifier("unit uninstall")
	oddID := workflow.NewWorkflowIdentifier("unit odd")

	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetWorkflows().Return([]workflow.Identifier{plainID, installID, uninstallID, oddID})
	engine.EXPECT().GetWorkflow(plainID).Return(mocks.NewMockEntry(ctrl), true)
	engine.EXPECT().GetWorkflow(installID).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)
	engine.EXPECT().GetWorkflow(uninstallID).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "uninstall"}), true)
	engine.EXPECT().GetWorkflow(oddID).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": 7, "lifecycle": "install"}), true)

	assert.Equal(t, []string{installID.String()}, idStrings(catalog.FindByLifecycle(engine, catalog.Install)))
}

func Test_FindByLifecycle_SkipsWorkflowMissingAtLookup(t *testing.T) {
	ctrl := gomock.NewController(t)
	goneID := workflow.NewWorkflowIdentifier("unit gone")
	nilID := workflow.NewWorkflowIdentifier("unit nil")
	keptID := workflow.NewWorkflowIdentifier("unit kept")

	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetWorkflows().Return([]workflow.Identifier{goneID, nilID, keptID})
	engine.EXPECT().GetWorkflow(goneID).Return(nil, false)
	engine.EXPECT().GetWorkflow(nilID).Return(nil, true)
	engine.EXPECT().GetWorkflow(keptID).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)

	assert.Equal(t, []string{keptID.String()}, idStrings(catalog.FindByLifecycle(engine, catalog.Install)))
}

func Test_FindByLifecycle_ReturnsSortedIDs(t *testing.T) {
	ctrl := gomock.NewController(t)
	a := workflow.NewWorkflowIdentifier("unit a")
	b := workflow.NewWorkflowIdentifier("unit b")
	c := workflow.NewWorkflowIdentifier("unit c")

	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetWorkflows().Return([]workflow.Identifier{c, a, b})
	engine.EXPECT().GetWorkflow(c).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)
	engine.EXPECT().GetWorkflow(a).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)
	engine.EXPECT().GetWorkflow(b).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)

	assert.Equal(t, []string{a.String(), b.String(), c.String()}, idStrings(catalog.FindByLifecycle(engine, catalog.Install)))
}

type replacingEngine struct {
	workflow.Engine
	replaceID  workflow.Identifier
	replaced   bool
	replaceErr error
}

func (e *replacingEngine) GetWorkflow(id workflow.Identifier) (workflow.Entry, bool) {
	if !e.replaced && id.String() == e.replaceID.String() {
		e.replaced = true
		_, e.replaceErr = e.Engine.Register(id, configOptions(), noopCallback)
	}
	return e.Engine.GetWorkflow(id)
}

func Test_FindByLifecycle_WorkflowReplacedAtLookup_UsesCurrentEntry(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	id := workflow.NewWorkflowIdentifier("unit replaced")
	_, err := catalog.Register(engine, id, configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
	require.NoError(t, err)
	wrapped := &replacingEngine{Engine: engine, replaceID: id}

	assert.Empty(t, catalog.FindByLifecycle(wrapped, catalog.Install))
	assert.True(t, wrapped.replaced)
	require.NoError(t, wrapped.replaceErr)
}

func Test_FindByLifecycle_ConcurrentWithRegistrationDoesNotRace(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	const count = 50
	idFor := func(i int) workflow.Identifier {
		return workflow.NewWorkflowIdentifier(fmt.Sprintf("concurrent catalog %02d", i))
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range count {
			_, err := catalog.Register(engine, idFor(i), configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
			assert.NoError(t, err)
		}
	})
	for range 2 {
		wg.Go(func() {
			for range count {
				ids := idStrings(catalog.FindByLifecycle(engine, catalog.Install))
				assert.True(t, slices.IsSorted(ids), "query results must be sorted")
			}
		})
	}
	wg.Wait()

	assert.Len(t, catalog.FindByLifecycle(engine, catalog.Install), count)
}
