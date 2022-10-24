package workflow

import (
	"net/url"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// typedefs
type Identifier = *url.URL
type Callback func(invocation InvocationContext, input []Data) ([]Data, error)

// interfaces
type Data interface {
	SetMetaData(key string, value string)
	GetMetaData(key string) (string, error)
	SetPayload(payload interface{})
	GetPayload() interface{}
	GetIdentifier() Identifier
	GetContentType() string
}

type InvocationContext interface {
	GetWorkflowIdentifier() Identifier
	GetConfiguration() configuration.Configuration
	GetEngine() Engine
	GetAnalytics() *analytics.Analytics
	//GetLogger()        // return logger instance
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
	Register(id Identifier, config ConfigurationOptions, callback Callback) (Entry, error)
	GetWorkflows() []Identifier
	GetWorkflow(id Identifier) (Entry, bool)
	Invoke(id Identifier) ([]Data, error)
	InvokeWithInput(id Identifier, input []Data) ([]Data, error)

	GetAnalytics() *analytics.Analytics
}
