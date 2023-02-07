package workflow

import (
	"log"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

// InvocationContextImpl is the default implementation of the InvocationContext interface.
type InvocationContextImpl struct {
	WorkflowID     Identifier
	WorkflowEngine *EngineImpl
	Configuration  configuration.Configuration
	Analytics      analytics.Analytics
	networkAccess  networking.NetworkAccess
	logger         *log.Logger
}

// GetWorkflowIdentifier returns the identifier of the workflow that is being invoked.
func (ici *InvocationContextImpl) GetWorkflowIdentifier() Identifier {
	return ici.WorkflowID
}

// GetConfiguration returns the configuration that can be used inside the workflow.
func (ici *InvocationContextImpl) GetConfiguration() configuration.Configuration {
	return ici.Configuration
}

// GetEngine returns the workflow engine that is invoking the workflow.
func (ici *InvocationContextImpl) GetEngine() Engine {
	return ici.WorkflowEngine
}

// GetAnalytics returns the analytics instance that is being used by the workflow engine.
func (ici *InvocationContextImpl) GetAnalytics() analytics.Analytics {
	return ici.Analytics
}

// GetNetworkAccess returns the network access instance that is being used by the workflow engine.
func (ici *InvocationContextImpl) GetNetworkAccess() networking.NetworkAccess {
	return ici.networkAccess
}

// GetLogger returns the logger instance that is being used by the workflow engine.
func (ici *InvocationContextImpl) GetLogger() *log.Logger {
	return ici.logger
}
