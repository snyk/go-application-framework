package catalog_test

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

var errEngine = errors.New("engine refused the registration")

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

func Test_Register(t *testing.T) {
	type metadataCall struct {
		value string
		err   error
	}
	tests := []struct {
		name         string
		engineErr    error
		setMetadata  *metadataCall
		opts         []catalog.RegisterOption
		wantNilEntry bool
		wantErr      error
	}{
		{name: "engine error is returned unchanged with a nil entry", engineErr: errEngine,
			opts: []catalog.RegisterOption{catalog.WithLifecycle(catalog.Install)}, wantNilEntry: true, wantErr: errEngine},
		{name: "without options nothing is written"},
		{name: "entry without metadata support returns the entry and ErrMetadataUnsupported",
			opts: []catalog.RegisterOption{catalog.WithLifecycle(catalog.Install)}, wantErr: catalog.ErrMetadataUnsupported},
		{name: "lifecycle is written under the label prefix", setMetadata: &metadataCall{value: "install"},
			opts: []catalog.RegisterOption{catalog.WithLifecycle(catalog.Install)}},
		{name: "repeated lifecycle keeps the last value and writes once", setMetadata: &metadataCall{value: "uninstall"},
			opts: []catalog.RegisterOption{catalog.WithLifecycle(catalog.Install), catalog.WithLifecycle(catalog.Uninstall)}},
		{name: "SetMetadata error is returned with the entry", setMetadata: &metadataCall{value: "install", err: errEngine},
			opts: []catalog.RegisterOption{catalog.WithLifecycle(catalog.Install)}, wantErr: errEngine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			var entry workflow.Entry
			switch {
			case tt.wantNilEntry:
			case tt.setMetadata != nil:
				withMetadata := newMetadataEntry(ctrl)
				withMetadata.MockEntryWithMetadata.EXPECT().SetMetadata("label:lifecycle", tt.setMetadata.value).Return(tt.setMetadata.err)
				entry = withMetadata
			default:
				entry = mocks.NewMockEntry(ctrl)
			}
			engine := engineReturning(ctrl, entry, tt.engineErr)

			got, err := catalog.Register(engine, workflow.NewWorkflowIdentifier("unit"), configOptions(), noopCallback, tt.opts...)

			if tt.wantNilEntry {
				assert.Nil(t, got)
			} else {
				assert.Equal(t, entry, got)
			}
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
