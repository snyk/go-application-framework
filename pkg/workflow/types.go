package workflow

import (
	"log"
	"net/url"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

//go:generate $GOPATH/bin/mockgen -source=types.go -destination ../mocks/workflow.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/workflow/

// typedefs
type Identifier = *url.URL
type Callback func(invocation InvocationContext, input []Data) ([]Data, error)
type ExtensionInit func(engine Engine) error

// interfaces
type Data interface {
	SetMetaData(key string, value string)
	GetMetaData(key string) (string, error)
	SetPayload(payload interface{})
	GetPayload() interface{}
	GetIdentifier() Identifier
	GetContentType() string
	GetContentLocation() string
	SetContentLocation(string)
}

type InvocationContext interface {
	GetWorkflowIdentifier() Identifier
	GetConfiguration() configuration.Configuration
	GetEngine() Engine
	GetAnalytics() analytics.Analytics
	GetNetworkAccess() networking.NetworkAccess
	GetLogger() *log.Logger
	//GetUserInterface() // return ui instance
}

type ConfigurationOptions interface {
}

type Entry interface {
	GetEntryPoint() Callback
	GetConfigurationOptions() ConfigurationOptions
	IsVisible() bool
	SetVisibility(visible bool)
}

type Engine interface {
	Init() error
	AddExtensionInitializer(initializer ExtensionInit)
	Register(id Identifier, config ConfigurationOptions, callback Callback) (Entry, error)
	GetWorkflows() []Identifier
	GetWorkflow(id Identifier) (Entry, bool)
	Invoke(id Identifier) ([]Data, error)
	InvokeWithInput(id Identifier, input []Data) ([]Data, error)
	InvokeWithConfig(id Identifier, config configuration.Configuration) ([]Data, error)
	InvokeWithInputAndConfig(id Identifier, input []Data, config configuration.Configuration) ([]Data, error)

	GetAnalytics() analytics.Analytics
	GetNetworkAccess() networking.NetworkAccess
	GetConfiguration() configuration.Configuration
}
