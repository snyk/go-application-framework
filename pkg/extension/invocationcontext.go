package extension

import (
	"context"
	"log"
	"os"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/ui/consoleui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// pluginInvocationContext is the plugin-side implementation of
// workflow.InvocationContext. It lets an extension's Handler be written exactly
// like an in-process workflow.Callback.
//
// Services that are "live" (backed by the host) in this phase: NetworkAccess
// (via the option C auth proxy) and Configuration (declared flags + the proxied
// API URL). Logger and UserInterface write to stderr, which go-plugin forwards
// to the host. Analytics is local and Engine is unavailable; bridging those is
// the next phase (see docs/dynamic-extensions-design.md).
type pluginInvocationContext struct {
	ctx         context.Context
	id          workflow.Identifier
	config      configuration.Configuration
	network     networking.NetworkAccess
	logger      *log.Logger
	zlogger     *zerolog.Logger
	ui          ui.UserInterface
	analytics   analytics.Analytics
	engine      workflow.Engine
	runtimeInfo runtimeinfo.RuntimeInfo
}

var _ workflow.InvocationContext = (*pluginInvocationContext)(nil)

// newPluginInvocationContext assembles the InvocationContext handed to an
// extension's handler. When hostClient is non-nil (the host offered callbacks),
// analytics and the engine are backed by the host: analytics flows into the
// host's batch and GetEngine().Invoke runs sibling workflows on the host.
func newPluginInvocationContext(ctx context.Context, id workflow.Identifier, config configuration.Configuration, proxyURL, proxyToken string, hostClient extensionpb.HostCallbackClient, ri runtimeinfo.RuntimeInfo) *pluginInvocationContext {
	// stdout is reserved for the go-plugin handshake/protocol, so everything
	// human-facing on the plugin side must go to stderr.
	zl := zerolog.New(os.Stderr).With().Timestamp().Logger()
	network := buildNetworkAccess(config, proxyURL, proxyToken)
	uiface := pluginUserInterface()

	if ri == nil {
		ri = runtimeinfo.New()
	}

	c := &pluginInvocationContext{
		ctx:         ctx,
		id:          id,
		config:      config,
		network:     network,
		logger:      log.New(os.Stderr, "", 0),
		zlogger:     &zl,
		ui:          uiface,
		runtimeInfo: ri,
	}

	if hostClient != nil {
		c.analytics = newRemoteAnalytics(ctx, hostClient)
		c.engine = &remoteEngine{
			ctx:         ctx,
			client:      hostClient,
			config:      config,
			baseConfig:  configSnapshot(config),
			network:     network,
			logger:      &zl,
			ui:          uiface,
			stats:       c.analytics,
			runtimeInfo: ri,
		}
	} else {
		c.analytics = analytics.New()
	}

	return c
}

// buildNetworkAccess constructs a NetworkAccess that routes through the host's
// loopback auth proxy when one was provided. The proxy base URL is installed as
// the configuration's API_URL so extension code can build request URLs the
// usual way, and the per-invocation secret is attached as a static header.
func buildNetworkAccess(config configuration.Configuration, proxyURL, proxyToken string) networking.NetworkAccess {
	if proxyURL != "" {
		config.Set(configuration.API_URL, proxyURL)
	}
	network := networking.NewNetworkAccess(config)
	if proxyToken != "" {
		network.AddHeaderField(proxyTokenHeader, proxyToken)
	}
	return network
}

func pluginUserInterface() ui.UserInterface {
	return consoleui.New(
		consoleui.WithInput(os.Stdin),
		consoleui.WithOutput(os.Stderr),
		consoleui.WithErrorOutput(os.Stderr),
		consoleui.WithProgressWriter(os.Stderr),
	)
}

func (c *pluginInvocationContext) Context() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

func (c *pluginInvocationContext) GetWorkflowIdentifier() workflow.Identifier { return c.id }
func (c *pluginInvocationContext) GetConfiguration() configuration.Configuration {
	return c.config
}
func (c *pluginInvocationContext) GetNetworkAccess() networking.NetworkAccess { return c.network }
func (c *pluginInvocationContext) GetAnalytics() analytics.Analytics          { return c.analytics }
func (c *pluginInvocationContext) GetLogger() *log.Logger                     { return c.logger }
func (c *pluginInvocationContext) GetEnhancedLogger() *zerolog.Logger         { return c.zlogger }
func (c *pluginInvocationContext) GetUserInterface() ui.UserInterface         { return c.ui }

// GetEngine returns an engine whose Invoke runs sibling workflows on the host,
// or nil when the host did not offer callbacks for this invocation.
func (c *pluginInvocationContext) GetEngine() workflow.Engine { return c.engine }

// GetRuntimeInfo returns the host's runtimeinfo.RuntimeInfo, mirrored across
// the process boundary by the caller. It is never nil, even when the host had
// none set, so workflow code written for in-process use (which assumes a
// non-nil result) behaves the same when run as an extension.
func (c *pluginInvocationContext) GetRuntimeInfo() runtimeinfo.RuntimeInfo { return c.runtimeInfo }
