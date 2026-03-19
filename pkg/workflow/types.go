package workflow

import (
	"context"
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
	Context() context.Context
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

// ConfigurationOptionsMetaData provides read access to Annotations on registered Configuration Options.
type ConfigurationOptionsMetaData interface {
	// GetConfigurationOptionAnnotation returns the first value for the given annotation on the named ConfigurationOption.
	// Returns ("", false) when the ConfigurationOption or annotation does not exist.
	GetConfigurationOptionAnnotation(name, annotation string) (string, bool)

	// ConfigurationOptionsByAnnotation returns all ConfigurationOption names whose annotation matches the given value.
	ConfigurationOptionsByAnnotation(annotation, value string) []string

	// ConfigurationOptionNameByAnnotation returns the ConfigurationOption name whose annotation equals value.
	// Useful for reverse-lookup: given a remote key, find the canonical ConfigurationOption name.
	// Returns ("", false) when no ConfigurationOption matches.
	ConfigurationOptionNameByAnnotation(annotation, value string) (string, bool)

	// GetConfigurationOptionType returns the pConfigurationOption type string (e.g. "bool", "string", "int") for the named ConfigurationOption.
	// Returns "" when the ConfigurationOption does not exist.
	GetConfigurationOptionType(name string) string

	// GetConfigurationOptionUsage returns the usage string for the named ConfigurationOption.
	// Returns "" when the ConfigurationOption does not exist.
	GetConfigurationOptionUsage(name string) string
}

// ConfigurationOptions is an interface that can be implemented by any type that can be used to pass configuration options to a workflow.
// It embeds ConfigurationOptionsMetaData so registered options expose annotation lookups without coupling callers to pflag.
type ConfigurationOptions interface {
	ConfigurationOptionsMetaData
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
