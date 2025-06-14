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
	WrappedEngine                   Engine
	defaultInstrumentationCollector analytics.InstrumentationCollector
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

func (e *engineWrapper) Invoke(id Identifier, opts ...EngineInvokeOption) ([]Data, error) {
	options := &engineRuntimeConfig{}
	for _, opt := range opts {
		opt(options)
	}

	// if no InstrumentationCollector is specified, and a default is available, the default be used
	if options.ic == nil && e.defaultInstrumentationCollector != nil {
		opts = append(opts, WithInstrumentationCollector(e.defaultInstrumentationCollector))
	}

	return e.WrappedEngine.Invoke(id, opts...)
}

func (e *engineWrapper) InvokeWithInput(id Identifier, input []Data) ([]Data, error) {
	return e.Invoke(id, WithInput(input))
}

func (e *engineWrapper) InvokeWithConfig(id Identifier, config configuration.Configuration) ([]Data, error) {
	return e.Invoke(id, WithConfig(config))
}

func (e *engineWrapper) InvokeWithInputAndConfig(id Identifier, input []Data, config configuration.Configuration) ([]Data, error) {
	return e.Invoke(id, WithInput(input), WithConfig(config))
}

func (e *engineWrapper) GetAnalytics() analytics.Analytics {
	return e.WrappedEngine.GetAnalytics()
}

func (e *engineWrapper) GetNetworkAccess() networking.NetworkAccess {
	return e.WrappedEngine.GetNetworkAccess()
}

func (e *engineWrapper) GetConfiguration() configuration.Configuration {
	return e.WrappedEngine.GetConfiguration()
}

func (e *engineWrapper) SetLogger(logger *zerolog.Logger) {
	e.WrappedEngine.SetLogger(logger)
}

func (e *engineWrapper) SetConfiguration(config configuration.Configuration) {
	e.WrappedEngine.SetConfiguration(config)
}

func (e *engineWrapper) GetLogger() *zerolog.Logger {
	return e.WrappedEngine.GetLogger()
}

func (e *engineWrapper) GetUserInterface() ui.UserInterface {
	return e.WrappedEngine.GetUserInterface()
}

func (e *engineWrapper) SetUserInterface(ui ui.UserInterface) {
	e.WrappedEngine.SetUserInterface(ui)
}

func (e *engineWrapper) GetRuntimeInfo() runtimeinfo.RuntimeInfo {
	return e.WrappedEngine.GetRuntimeInfo()
}

func (e *engineWrapper) SetRuntimeInfo(ri runtimeinfo.RuntimeInfo) {
	e.WrappedEngine.SetRuntimeInfo(ri)
}
