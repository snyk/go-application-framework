package localworkflows

import (
	"log"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_Code_codeWorkflowEntryPoint_happyPath(t *testing.T) {
	// set
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	engine := mocks.NewMockEngine(gomock.NewController(t))

	// Mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	os.Args = []string{"cmd", "-user=bla"}

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetEngine().Return(engine).AnyTimes()
	engine.EXPECT().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config).Return(nil, nil)

	t.Run("invokes legacycli workflow", func(t *testing.T) {
		// run
		_, err := codeWorkflowEntryPoint(invocationContextMock, nil)

		assert.Equal(t, []string{"-user=bla"}, config.GetStringSlice(configuration.RAW_CMD_ARGS))
		assert.Nil(t, err)
	})

	// Write to stderr if any unsupported flags are passed
	// Future work: Stop passing through unsupported flags
}
