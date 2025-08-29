package workflow

import (
	"log"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
)

//go:generate go tool github.com/golang/mock/mockgen -source=types.go -destination ../mocks/workflow.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/workflow/

// typedefs
type Identifier = *url.URL
type Callback func(invocation InvocationContext, input []Data) ([]Data, error)
type ExtensionInit func(engine Engine) error

// interfaces

// Data is an interface that wraps the methods that are used to manage data that is passed between workflows.
type Data interface {
	SetMetaData(key string, value string)
	GetMetaData(key string) (string, error)
	SetPayload(payload interface{})
	GetPayload() interface{}
	GetIdentifier() Identifier
	GetContentType() string
	GetContentLocation() string
	SetContentLocation(string)
	AddError(err snyk_errors.Error)
	GetErrorList() []snyk_errors.Error
}

// InvocationContext is an interface that wraps various context information that is passed to a workflow when it is invoked.
type InvocationContext interface {
	GetWorkflowIdentifier() Identifier
	GetConfiguration() configuration.Configuration
	GetEngine() Engine
	GetAnalytics() analytics.Analytics
	GetNetworkAccess() networking.NetworkAccess
	GetLogger() *log.Logger
	GetEnhancedLogger() *zerolog.Logger
	GetUserInterface() ui.UserInterface
	GetRuntimeInfo() runtimeinfo.RuntimeInfo
}

// ConfigurationOptions is an interface that can be implemented by any type that can be used to pass configuration options to a workflow.
type ConfigurationOptions interface {
}

// Entry is an interface that wraps the methods that are used to manage workflow entries.
type Entry interface {
	GetEntryPoint() Callback
	GetConfigurationOptions() ConfigurationOptions
	IsVisible() bool
	SetVisibility(visible bool)
}

// Engine is the interface that wraps the methods that are used to manage workflows.
type Engine interface {
	Init() error
	AddExtensionInitializer(initializer ExtensionInit)
	Register(id Identifier, config ConfigurationOptions, callback Callback) (Entry, error)
	GetWorkflows() []Identifier
	GetWorkflow(id Identifier) (Entry, bool)
	Invoke(id Identifier, opts ...EngineInvokeOption) ([]Data, error)
	InvokeWithInput(id Identifier, input []Data) ([]Data, error)
	InvokeWithConfig(id Identifier, config configuration.Configuration) ([]Data, error)
	InvokeWithInputAndConfig(id Identifier, input []Data, config configuration.Configuration) ([]Data, error)

	GetAnalytics() analytics.Analytics
	GetNetworkAccess() networking.NetworkAccess
	GetConfiguration() configuration.Configuration
	SetLogger(logger *zerolog.Logger)
	SetConfiguration(config configuration.Configuration)
	GetLogger() *zerolog.Logger
	GetUserInterface() ui.UserInterface
	SetUserInterface(ui ui.UserInterface)
	GetRuntimeInfo() runtimeinfo.RuntimeInfo
	SetRuntimeInfo(ri runtimeinfo.RuntimeInfo)
}
