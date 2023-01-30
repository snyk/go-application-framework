package workflow

import (
	"log"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

type InvocationContextImpl struct {
	WorkflowID        Identifier
	WorkflowEngine    *EngineImpl
	Configuration     configuration.Configuration
	Analytics         analytics.Analytics
	OutputDestination OutputDestination
	networkAccess     networking.NetworkAccess
	logger            *log.Logger
}

func (ici *InvocationContextImpl) GetWorkflowIdentifier() Identifier {
	return ici.WorkflowID
}

func (ici *InvocationContextImpl) GetConfiguration() configuration.Configuration {
	return ici.Configuration
}

func (ici *InvocationContextImpl) GetEngine() Engine {
	return ici.WorkflowEngine
}

func (ici *InvocationContextImpl) GetAnalytics() analytics.Analytics {
	return ici.Analytics
}

func (ici *InvocationContextImpl) GetNetworkAccess() networking.NetworkAccess {
	return ici.networkAccess
}

func (ici *InvocationContextImpl) GetLogger() *log.Logger {
	return ici.logger
}

func (ici *InvocationContextImpl) GetOutputDestination() OutputDestination {
	return ici.OutputDestination
}
