package workflow

import (
	"log"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
)

func NewInvocationContext(
	id Identifier,
	config configuration.Configuration,
	engine Engine,
	network networking.NetworkAccess,
	logger zerolog.Logger,
	analyticsImpl analytics.Analytics,
	ui ui.UserInterface,
) InvocationContextImpl {
	return InvocationContextImpl{
		WorkflowID:     id,
		Configuration:  config,
		WorkflowEngine: engine,
		networkAccess:  network,
		logger:         &logger,
		Analytics:      analyticsImpl,
		ui:             ui,
	}
}

// InvocationContextImpl is the default implementation of the InvocationContext interface.
type InvocationContextImpl struct {
	WorkflowID     Identifier
	WorkflowEngine Engine
	Configuration  configuration.Configuration
	Analytics      analytics.Analytics
	networkAccess  networking.NetworkAccess
	logger         *zerolog.Logger
	ui             ui.UserInterface
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

// Deprecated: GetLogger returns the logger instance that is being used by the workflow engine.
func (ici *InvocationContextImpl) GetLogger() *log.Logger {
	return log.New(&utils.ToZeroLogDebug{Logger: ici.logger}, "", 0)
}

// GetEnhancedLogger returns the logger instance that is being used by the workflow engine.
func (ici *InvocationContextImpl) GetEnhancedLogger() *zerolog.Logger {
	return ici.logger
}

func (ici *InvocationContextImpl) GetUserInterface() ui.UserInterface {
	return ici.ui
}
