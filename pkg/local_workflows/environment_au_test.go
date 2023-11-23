package localworkflows

import (
	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"testing"
)

func Test_EnvironmentAu_setsEndpoint(t *testing.T) {
	// setup
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	ctrl := gomock.NewController(t)
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes().Return(&workflow.EntryImpl{}, nil)

	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	err := InitAuEnvironmentWorkflow(engine)
	require.NoError(t, err)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()

	_, err = auEnvironmentEntrypoint(invocationContextMock, []workflow.Data{})
	require.NoError(t, err)

	actual := config.GetString("endpoint")
	require.Equal(t, "https://app.au.snyk.io/api", actual)
}
