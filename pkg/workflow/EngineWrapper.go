package workflow

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
)

type engineWrapper struct {
	WrappedEngine Engine
}

var _ Engine = (*engineWrapper)(nil)

func (e *engineWrapper) Init() error {
	return e.WrappedEngine.Init()
}

func (e *engineWrapper) AddExtensionInitializer(initializer ExtensionInit) {
	e.WrappedEngine.AddExtensionInitializer(initializer)
}

func (e *engineWrapper) Register(id Identifier, config ConfigurationOptions, callback Callback) (Entry, error) {
	return e.WrappedEngine.Register(id, config, callback)
}

func (e *engineWrapper) GetWorkflows() []Identifier {
	return e.WrappedEngine.GetWorkflows()
}

func (e *engineWrapper) GetWorkflow(id Identifier) (Entry, bool) {
	return e.WrappedEngine.GetWorkflow(id)
}

func (e *engineWrapper) Invoke(id Identifier) ([]Data, error) {
	return e.WrappedEngine.Invoke(id)
}

func (e *engineWrapper) InvokeWithInput(id Identifier, input []Data) ([]Data, error) {
	return e.WrappedEngine.InvokeWithInput(id, input)
}

func (e *engineWrapper) InvokeWithConfig(id Identifier, config configuration.Configuration) ([]Data, error) {
	return e.WrappedEngine.InvokeWithConfig(id, config)
}

func (e *engineWrapper) InvokeWithInputAndConfig(id Identifier, input []Data, config configuration.Configuration) ([]Data, error) {
	return e.WrappedEngine.InvokeWithInputAndConfig(id, input, config)
}

func (e *engineWrapper) GetAnalytics() analytics.Analytics {
	return e.GetAnalytics()
}

func (e *engineWrapper) GetNetworkAccess() networking.NetworkAccess {
	return e.GetNetworkAccess()
}

func (e *engineWrapper) GetConfiguration() configuration.Configuration {
	return e.GetConfiguration()
}

func (e *engineWrapper) SetLogger(logger *zerolog.Logger) {
	e.SetLogger(logger)
}

func (e *engineWrapper) SetConfiguration(config configuration.Configuration) {
	e.SetConfiguration(config)
}

func (e *engineWrapper) GetLogger() *zerolog.Logger {
	return e.GetLogger()
}

func (e *engineWrapper) GetUserInterface() ui.UserInterface {
	return e.GetUserInterface()
}

func (e *engineWrapper) SetUserInterface(ui ui.UserInterface) {
	e.SetUserInterface(ui)
}

func (e *engineWrapper) GetRuntimeInfo() runtimeinfo.RuntimeInfo {
	return e.GetRuntimeInfo()
}

func (e *engineWrapper) SetRuntimeInfo(ri runtimeinfo.RuntimeInfo) {
	e.SetRuntimeInfo(ri)
}
