package extension

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// remoteAnalytics forwards instrumentation to the host over the HostCallback
// channel, so extension analytics land in the host's batch. It embeds a local
// analytics.Analytics to satisfy the full interface; only the extension-facing
// recording methods are overridden to also forward.
type remoteAnalytics struct {
	analytics.Analytics
	ctx    context.Context
	client extensionpb.HostCallbackClient
}

func newRemoteAnalytics(ctx context.Context, client extensionpb.HostCallbackClient) *remoteAnalytics {
	return &remoteAnalytics{Analytics: analytics.New(), ctx: ctx, client: client}
}

func (a *remoteAnalytics) AddExtensionStringValue(key string, value string) {
	a.Analytics.AddExtensionStringValue(key, value)
	_, _ = a.client.AddExtensionValue(a.ctx, &extensionpb.ExtensionValue{
		Key:   key,
		Value: &extensionpb.ExtensionValue_StringValue{StringValue: value},
	})
}

func (a *remoteAnalytics) AddExtensionIntegerValue(key string, value int) {
	a.Analytics.AddExtensionIntegerValue(key, value)
	_, _ = a.client.AddExtensionValue(a.ctx, &extensionpb.ExtensionValue{
		Key:   key,
		Value: &extensionpb.ExtensionValue_IntValue{IntValue: int64(value)},
	})
}

func (a *remoteAnalytics) AddExtensionBoolValue(key string, value bool) {
	a.Analytics.AddExtensionBoolValue(key, value)
	_, _ = a.client.AddExtensionValue(a.ctx, &extensionpb.ExtensionValue{
		Key:   key,
		Value: &extensionpb.ExtensionValue_BoolValue{BoolValue: value},
	})
}

func (a *remoteAnalytics) AddError(err error) {
	a.Analytics.AddError(err)
	if err != nil {
		_, _ = a.client.ReportError(a.ctx, &extensionpb.ReportErrorRequest{Message: err.Error()})
	}
}

// remoteEngine is the plugin-side workflow.Engine. Invoke and its variants
// forward to the host engine over the HostCallback channel so an extension can
// run sibling workflows; the host runs them in its full context. Accessors
// return the extension's own invocation services. Registration/lifecycle
// methods are not meaningful across the boundary.
type remoteEngine struct {
	ctx     context.Context
	client  extensionpb.HostCallbackClient
	config  configuration.Configuration
	network networking.NetworkAccess
	logger  *zerolog.Logger
	ui      ui.UserInterface
	stats   analytics.Analytics
}

var _ workflow.Engine = (*remoteEngine)(nil)

func (e *remoteEngine) invoke(id workflow.Identifier, input []workflow.Data) ([]workflow.Data, error) {
	inMsgs, err := dataSliceToMsgs(input)
	if err != nil {
		return nil, fmt.Errorf("serializing input: %w", err)
	}
	resp, err := e.client.Invoke(e.ctx, &extensionpb.InvokeRequest{
		Identifier: id.String(),
		Input:      inMsgs,
	})
	if err != nil {
		return nil, err
	}
	return msgsToDataSlice(resp.GetOutput(), e.config)
}

func (e *remoteEngine) Invoke(id workflow.Identifier, opts ...workflow.EngineInvokeOption) ([]workflow.Data, error) {
	_, input := workflow.ResolveInvokeOptions(e.config, opts...)
	return e.invoke(id, input)
}

func (e *remoteEngine) InvokeWithInput(id workflow.Identifier, input []workflow.Data) ([]workflow.Data, error) {
	return e.invoke(id, input)
}

// InvokeWithConfig forwards the invocation; per-invocation config overrides are
// not propagated across the boundary (the sibling runs with the host's config).
func (e *remoteEngine) InvokeWithConfig(id workflow.Identifier, _ configuration.Configuration) ([]workflow.Data, error) {
	return e.invoke(id, nil)
}

func (e *remoteEngine) InvokeWithInputAndConfig(id workflow.Identifier, input []workflow.Data, _ configuration.Configuration) ([]workflow.Data, error) {
	return e.invoke(id, input)
}

func (e *remoteEngine) GetConfiguration() configuration.Configuration { return e.config }
func (e *remoteEngine) GetNetworkAccess() networking.NetworkAccess    { return e.network }
func (e *remoteEngine) GetAnalytics() analytics.Analytics             { return e.stats }
func (e *remoteEngine) GetLogger() *zerolog.Logger                    { return e.logger }
func (e *remoteEngine) GetUserInterface() ui.UserInterface            { return e.ui }
func (e *remoteEngine) GetRuntimeInfo() runtimeinfo.RuntimeInfo       { return nil }
func (e *remoteEngine) GetWorkflows() []workflow.Identifier           { return nil }
func (e *remoteEngine) GetWorkflow(workflow.Identifier) (workflow.Entry, bool) {
	return nil, false
}

// The following are host-only concerns and are no-ops (or errors) for an
// extension running across the process boundary.
func (e *remoteEngine) Init() error                                    { return nil }
func (e *remoteEngine) AddExtensionInitializer(workflow.ExtensionInit) {}
func (e *remoteEngine) Register(workflow.Identifier, workflow.ConfigurationOptions, workflow.Callback) (workflow.Entry, error) {
	return nil, fmt.Errorf("engine.Register is not supported from within an extension")
}
func (e *remoteEngine) SetLogger(*zerolog.Logger)                    {}
func (e *remoteEngine) SetConfiguration(configuration.Configuration) {}
func (e *remoteEngine) SetUserInterface(ui.UserInterface)            {}
func (e *remoteEngine) SetRuntimeInfo(runtimeinfo.RuntimeInfo)       {}
