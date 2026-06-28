// Package extension implements dynamic, out-of-process loading of CLI
// extensions. An extension is a standalone binary that the host launches via
// hashicorp/go-plugin and communicates with over gRPC. Extension code never
// runs inside the host's address space; the process boundary is the isolation
// boundary.
//
// The host side ([Loader]) discovers extension binaries and registers a proxy
// workflow for each workflow an extension provides. The plugin side ([Serve])
// is the SDK an extension author uses to expose their workflows.
package extension

import (
	"context"

	plugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
)

// pluginName is the key under which the Extension plugin is registered in the
// go-plugin plugin map. Host and plugin must agree on it.
const pluginName = "snyk_extension"

// Handshake is the go-plugin handshake shared by the host and every extension.
// A mismatch (wrong magic cookie or protocol version) makes go-plugin refuse
// the connection before any extension code runs, so a stray executable cannot
// be mistaken for a Snyk extension.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "SNYK_CLI_EXTENSION",
	MagicCookieValue: "snyk-extension-v1-handshake",
}

// grpcPlugin adapts the Extension gRPC service to go-plugin. One type serves
// both ends: on the plugin side impl is non-nil and backs the gRPC server; on
// the host side impl is nil and GRPCClient hands back a client adapter.
type grpcPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl extensionpb.ExtensionServer
}

var _ plugin.GRPCPlugin = (*grpcPlugin)(nil)

func (p *grpcPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	extensionpb.RegisterExtensionServer(s, p.impl)
	return nil
}

func (p *grpcPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &grpcClient{client: extensionpb.NewExtensionClient(c)}, nil
}

// pluginMap builds the go-plugin plugin map. impl is non-nil only on the plugin
// side.
func pluginMap(impl extensionpb.ExtensionServer) map[string]plugin.Plugin {
	return map[string]plugin.Plugin{
		pluginName: &grpcPlugin{impl: impl},
	}
}

// executeRequest is the host-side, transport-agnostic form of an Execute call.
type executeRequest struct {
	identifier        string
	config            map[string]string
	input             []*extensionpb.DataMsg
	networkProxyURL   string
	networkProxyToken string
}

// pluginConn is the host-side view of a connected extension. It is an interface
// so the Loader can be unit-tested with an in-memory fake instead of a real
// subprocess.
type pluginConn interface {
	Discover(ctx context.Context) ([]*extensionpb.WorkflowSpec, error)
	Execute(ctx context.Context, req executeRequest) ([]*extensionpb.DataMsg, error)
}

// grpcClient is the gRPC-backed implementation of pluginConn.
type grpcClient struct {
	client extensionpb.ExtensionClient
}

var _ pluginConn = (*grpcClient)(nil)

func (c *grpcClient) Discover(ctx context.Context) ([]*extensionpb.WorkflowSpec, error) {
	resp, err := c.client.Discover(ctx, &extensionpb.DiscoverRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetWorkflows(), nil
}

func (c *grpcClient) Execute(ctx context.Context, req executeRequest) ([]*extensionpb.DataMsg, error) {
	resp, err := c.client.Execute(ctx, &extensionpb.ExecuteRequest{
		Identifier:        req.identifier,
		Config:            req.config,
		Input:             req.input,
		NetworkProxyUrl:   req.networkProxyURL,
		NetworkProxyToken: req.networkProxyToken,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetOutput(), nil
}
