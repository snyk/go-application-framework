package catalog_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

var errEngine = errors.New("engine refused the registration")

// metadataEntry is a test entry that is both a workflow.Entry and a workflow.EntryWithMetadata. It is composed from the two
// generated mocks, so no combined interface has to be added to the public API just for tests.
type metadataEntry struct {
	*mocks.MockEntry
	*mocks.MockEntryWithMetadata
}

func newMetadataEntry(ctrl *gomock.Controller) metadataEntry {
	return metadataEntry{mocks.NewMockEntry(ctrl), mocks.NewMockEntryWithMetadata(ctrl)}
}

func engineReturning(ctrl *gomock.Controller, entry workflow.Entry, err error) *mocks.MockEngine {
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(entry, err)
	return engine
}

// Unit: an error from engine.Register is returned unchanged, together with the nil entry the engine returned.
func Test_Register_EngineError_ReturnedUnchanged(t *testing.T) {
	ctrl := gomock.NewController(t)
	engine := engineReturning(ctrl, nil, errEngine)

	entry, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
	assert.Nil(t, entry)
	assert.ErrorIs(t, err, errEngine)
}

// Unit: without options, the entry from engine.Register is returned and nothing is written to it.
func Test_Register_WithoutOptions_ReturnsEngineEntry(t *testing.T) {
	ctrl := gomock.NewController(t)
	entry := mocks.NewMockEntry(ctrl)
	engine := engineReturning(ctrl, entry, nil)

	got, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback)
	require.NoError(t, err)
	assert.Equal(t, entry, got)
}

// Unit: an entry without metadata support is returned with ErrMetadataUnsupported; nothing can be labeled on it.
func Test_Register_EntryWithoutMetadata_ReturnsEntryAndError(t *testing.T) {
	ctrl := gomock.NewController(t)
	entry := mocks.NewMockEntry(ctrl)
	engine := engineReturning(ctrl, entry, nil)

	got, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
	assert.Equal(t, entry, got)
	assert.ErrorIs(t, err, catalog.ErrMetadataUnsupported)
}

// Unit: the lifecycle label is written to the entry metadata under the reserved label prefix.
func Test_Register_WithLifecycle_WritesLabelToMetadata(t *testing.T) {
	ctrl := gomock.NewController(t)
	entry := newMetadataEntry(ctrl)
	entry.MockEntryWithMetadata.EXPECT().SetMetadata("label:lifecycle", "install").Return(nil)
	engine := engineReturning(ctrl, entry, nil)

	got, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
	require.NoError(t, err)
	assert.Equal(t, entry, got)
}

// Unit: one value per label. Passing the lifecycle option twice keeps the last value and writes only that one.
func Test_Register_RepeatedLifecycle_KeepsLastValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	entry := newMetadataEntry(ctrl)
	entry.MockEntryWithMetadata.EXPECT().SetMetadata("label:lifecycle", "uninstall").Return(nil)
	engine := engineReturning(ctrl, entry, nil)

	_, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback,
		catalog.WithLifecycle(catalog.Install), catalog.WithLifecycle(catalog.Uninstall))
	require.NoError(t, err)
}

// Unit: an error from SetMetadata is returned together with the entry.
func Test_Register_SetMetadataError_ReturnedWithEntry(t *testing.T) {
	ctrl := gomock.NewController(t)
	entry := newMetadataEntry(ctrl)
	entry.MockEntryWithMetadata.EXPECT().SetMetadata("label:lifecycle", "install").Return(errEngine)
	engine := engineReturning(ctrl, entry, nil)

	got, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback, catalog.WithLifecycle(catalog.Install))
	assert.Equal(t, entry, got)
	assert.ErrorIs(t, err, errEngine)
}
