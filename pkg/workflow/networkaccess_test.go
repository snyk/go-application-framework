package workflow_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func TestCreateNetworkAccessFromEngine_EngineConfigurationUsesEngineNetworkAccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	config := configuration.NewInMemory()
	engineNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	engine.EXPECT().GetNetworkAccess().Return(engineNetworkAccess).AnyTimes()

	// no Clone or SetConfiguration is expected, an unexpected call fails the test
	require.Same(t, engineNetworkAccess, workflow.CreateNetworkAccessFromEngine(engine, config))
}

func TestCreateNetworkAccessFromEngine_OtherConfigurationUsesCloneBoundToIt(t *testing.T) {
	ctrl := gomock.NewController(t)
	config := configuration.NewInMemory()
	other := config.Clone()
	engineNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	clone := mocks.NewMockNetworkAccess(ctrl)
	engine := mocks.NewMockEngine(ctrl)
	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	engine.EXPECT().GetNetworkAccess().Return(engineNetworkAccess).AnyTimes()
	engineNetworkAccess.EXPECT().Clone().Return(clone)
	clone.EXPECT().SetConfiguration(other)

	require.Same(t, clone, workflow.CreateNetworkAccessFromEngine(engine, other))
}

func TestCreateNetworkAccessFromEngine_EngineConfigurationReturnsEngineNetworkAccess(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)
	require.NoError(t, engine.Init())

	require.Same(t, engine.GetNetworkAccess(), workflow.CreateNetworkAccessFromEngine(engine, engine.GetConfiguration()))
}

func TestCreateNetworkAccessFromEngine_ConfigurationSetOnEngineUsesEngineNetworkAccess(t *testing.T) {
	oldConfig := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(oldConfig)
	require.NoError(t, engine.Init())
	newConfig := oldConfig.Clone()
	newConfig.Set(configuration.API_URL, "https://api.eu.snyk.io")
	engine.SetConfiguration(newConfig)

	require.Same(t, engine.GetNetworkAccess(), workflow.CreateNetworkAccessFromEngine(engine, newConfig))

	previous := workflow.CreateNetworkAccessFromEngine(engine, oldConfig)
	require.NotSame(t, engine.GetNetworkAccess(), previous)
	require.Same(t, oldConfig, previous.GetConfiguration())
}

func TestCreateNetworkAccessFromEngine_CloneKeepsEngineNetworkAccessOnEngineConfiguration(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)
	require.NoError(t, engine.Init())
	other := config.Clone()
	other.Set(configuration.API_URL, "https://api.eu.snyk.io")

	networkAccess := workflow.CreateNetworkAccessFromEngine(engine, other)

	require.NotSame(t, engine.GetNetworkAccess(), networkAccess)
	require.Same(t, other, networkAccess.GetConfiguration())
	require.Same(t, config, engine.GetNetworkAccess().GetConfiguration())
}

func TestCreateNetworkAccess_ReturnsCloneBoundToConfiguration(t *testing.T) {
	config := configuration.NewInMemory()
	base := networking.NewNetworkAccess(config)
	other := configuration.NewInMemory()

	bound := workflow.CreateNetworkAccess(base, other)

	require.NotNil(t, bound)
	require.NotSame(t, base, bound, "must always return a fresh clone")
	require.Same(t, other, bound.GetConfiguration())
	require.Same(t, config, base.GetConfiguration(), "base network access must keep its configuration")
}

func TestCreateNetworkAccess_AlwaysClonesEvenForBaseConfiguration(t *testing.T) {
	config := configuration.NewInMemory()
	base := networking.NewNetworkAccess(config)

	bound := workflow.CreateNetworkAccess(base, config)

	assert.NotSame(t, base, bound)
	assert.Same(t, config, bound.GetConfiguration())
}
