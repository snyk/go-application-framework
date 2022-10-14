package workflow

import (
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type InvocationContextImpl struct {
	WorkflowID     Identifier
	WorkflowEngine *EngineImpl
	Configuration  configuration.Configuration
	Analytics      *analytics.Analytics
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

func (ici *InvocationContextImpl) GetAnalytics() *analytics.Analytics {
	return ici.Analytics
}
