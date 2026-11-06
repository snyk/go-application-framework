package catalog_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

func Test_PanicError_ReportsOnlyTypeOfValue(t *testing.T) {
	err := &catalog.PanicError{Value: "token=secret"}
	assert.Equal(t, "workflow callback panicked (string)", err.Error())
	assert.NotContains(t, err.Error(), "secret")
}

func Test_RunLifecycle_ReportsProgressThroughUserInterface(t *testing.T) {
	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	self := workflow.NewWorkflowIdentifier("unit runner")
	alpha := workflow.NewWorkflowIdentifier("unit alpha")
	beta := workflow.NewWorkflowIdentifier("unit beta")

	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetWorkflows().Return([]workflow.Identifier{beta, self, alpha})
	engine.EXPECT().GetWorkflow(self).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)
	engine.EXPECT().GetWorkflow(alpha).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)
	engine.EXPECT().GetWorkflow(beta).Return(labeledEntry(ctrl, map[string]any{"label:lifecycle": "install"}), true)
	engine.EXPECT().Invoke(alpha, gomock.Any()).Return(nil, nil)
	engine.EXPECT().Invoke(beta, gomock.Any()).Return(nil, nil)

	bar := mocks.NewMockProgressBar(ctrl)
	bar.EXPECT().SetTitle("Running install steps")
	bar.EXPECT().UpdateProgress(0.0).Return(nil)
	bar.EXPECT().UpdateProgress(0.5).Return(nil)
	bar.EXPECT().Clear().Return(nil)

	userInterface := mocks.NewMockUserInterface(ctrl)
	userInterface.EXPECT().NewProgressBar().Return(bar)

	ic := mocks.NewMockInvocationContext(ctrl)
	ic.EXPECT().Context().Return(context.Background()).AnyTimes()
	ic.EXPECT().GetWorkflowIdentifier().Return(self)
	ic.EXPECT().GetEngine().Return(engine)
	ic.EXPECT().GetUserInterface().Return(userInterface)
	ic.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	assert.Nil(t, catalog.RunLifecycle(ic, catalog.Install))
}
