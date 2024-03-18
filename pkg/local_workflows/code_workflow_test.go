package localworkflows

import (
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	// set
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitCodeWorkflow(engine)
	assert.NoError(t, err)

	err = InitCodeWorkflow(engine)
	assert.NoError(t, err)

	// Verify that the workflow is registered with the correct id
	wrkflw, ok := engine.GetWorkflow(WORKFLOWID_CODE)
	assert.True(t, ok)
	assert.NotNil(t, wrkflw)
}

func Test_Code_codeWorkflowEntryPoint_happyPath(t *testing.T) {
	// set
	logger := zerolog.Logger{}
	config := configuration.New()
	engine := mocks.NewMockEngine(gomock.NewController(t))

	// Mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	os.Args = []string{"cmd", "-user=bla"}

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engine).AnyTimes()
	engine.EXPECT().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config).Return(nil, nil)

	t.Run("invokes legacycli workflow", func(t *testing.T) {
		// run
		_, err := codeWorkflowEntryPoint(invocationContextMock, nil)

		assert.Equal(t, []string{"-user=bla"}, config.GetStringSlice(configuration.RAW_CMD_ARGS))
		assert.Nil(t, err)
	})
}
