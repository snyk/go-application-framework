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
) InvocationContext {
	return &invocationContextImpl{
		WorkflowID:     id,
		Configuration:  config,
		WorkflowEngine: engine,
		networkAccess:  network,
		logger:         &logger,
		Analytics:      analyticsImpl,
		ui:             ui,
	}
}

// invocationContextImpl is the default implementation of the InvocationContext interface.
type invocationContextImpl struct {
	WorkflowID     Identifier
	WorkflowEngine Engine
	Configuration  configuration.Configuration
	Analytics      analytics.Analytics
	networkAccess  networking.NetworkAccess
	logger         *zerolog.Logger
	ui             ui.UserInterface
}

// GetWorkflowIdentifier returns the identifier of the workflow that is being invoked.
func (ici *invocationContextImpl) GetWorkflowIdentifier() Identifier {
	return ici.WorkflowID
}

// GetConfiguration returns the configuration that can be used inside the workflow.
func (ici *invocationContextImpl) GetConfiguration() configuration.Configuration {
	return ici.Configuration
}

// GetEngine returns the workflow engine that is invoking the workflow.
func (ici *invocationContextImpl) GetEngine() Engine {
	return ici.WorkflowEngine
}

// GetAnalytics returns the analytics instance that is being used by the workflow engine.
func (ici *invocationContextImpl) GetAnalytics() analytics.Analytics {
	return ici.Analytics
}

// GetNetworkAccess returns the network access instance that is being used by the workflow engine.
func (ici *invocationContextImpl) GetNetworkAccess() networking.NetworkAccess {
	return ici.networkAccess
}

// Deprecated: GetLogger returns the logger instance that is being used by the workflow engine.
func (ici *invocationContextImpl) GetLogger() *log.Logger {
	return log.New(&utils.ToZeroLogDebug{Logger: ici.logger}, "", 0)
}

// GetEnhancedLogger returns the logger instance that is being used by the workflow engine.
func (ici *invocationContextImpl) GetEnhancedLogger() *zerolog.Logger {
	return ici.logger
}

func (ici *invocationContextImpl) GetUserInterface() ui.UserInterface {
	return ici.ui
}
