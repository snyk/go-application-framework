package extension

import (
	"context"
	"net/url"
	"strconv"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/pflag"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Handler is the plugin-side implementation of a single workflow. It is exactly
// workflow.Callback: it receives a workflow.InvocationContext (configuration,
// network access, logger, UI) and the input data, and returns output data. An
// existing in-process workflow callback can be registered as an extension
// without changing its signature.
type Handler = workflow.Callback

// Registrar is handed to the register callback passed to Serve. Extension
// authors use it to declare the workflows their binary provides.
type Registrar interface {
	// Register adds a workflow. identifier is a workflow identifier string such
	// as "flw://hello" (see workflow.NewWorkflowIdentifier).
	Register(identifier string, handler Handler, opts ...WorkflowOption)
}

// WorkflowOption configures a registered workflow.
type WorkflowOption func(*workflowRegistration)

// WithFlags declares the configuration flags the workflow understands. The host
// uses them to build CLI flags and, at execution time, exports only these keys
// to the extension.
func WithFlags(flags *pflag.FlagSet) WorkflowOption {
	return func(r *workflowRegistration) {
		r.flags = flags
	}
}

// Hidden marks the workflow as not directly invokable from the CLI help/usage.
func Hidden() WorkflowOption {
	return func(r *workflowRegistration) {
		r.visible = false
	}
}

type workflowRegistration struct {
	identifier string
	handler    Handler
	flags      *pflag.FlagSet
	visible    bool
}

// serveHandler implements both Registrar (plugin author API) and the generated
// ExtensionServer (gRPC service the host calls).
type serveHandler struct {
	extensionpb.UnimplementedExtensionServer
	workflows map[string]*workflowRegistration
	order     []string // preserves registration order for stable Discover output
}

func newServeHandler() *serveHandler {
	return &serveHandler{workflows: map[string]*workflowRegistration{}}
}

var (
	_ Registrar                   = (*serveHandler)(nil)
	_ extensionpb.ExtensionServer = (*serveHandler)(nil)
)

func (h *serveHandler) Register(identifier string, handler Handler, opts ...WorkflowOption) {
	reg := &workflowRegistration{identifier: identifier, handler: handler, visible: true}
	for _, opt := range opts {
		opt(reg)
	}
	if _, exists := h.workflows[identifier]; !exists {
		h.order = append(h.order, identifier)
	}
	h.workflows[identifier] = reg
}

func (h *serveHandler) Discover(_ context.Context, _ *extensionpb.DiscoverRequest) (*extensionpb.DiscoverResponse, error) {
	resp := &extensionpb.DiscoverResponse{}
	for _, id := range h.order {
		reg := h.workflows[id]
		resp.Workflows = append(resp.Workflows, &extensionpb.WorkflowSpec{
			Identifier: reg.identifier,
			Visible:    reg.visible,
			Flags:      flagsToSpecs(reg.flags),
		})
	}
	return resp, nil
}

func (h *serveHandler) Execute(ctx context.Context, req *extensionpb.ExecuteRequest) (*extensionpb.ExecuteResponse, error) {
	reg, ok := h.workflows[req.GetIdentifier()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "workflow %q not provided by this extension", req.GetIdentifier())
	}

	config := configFromSnapshot(req.GetConfig(), reg.flags)

	input, err := msgsToDataSlice(req.GetInput(), config)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decoding input: %v", err)
	}

	id, err := url.Parse(req.GetIdentifier())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing identifier: %v", err)
	}

	invocation := newPluginInvocationContext(ctx, id, config, req.GetNetworkProxyUrl(), req.GetNetworkProxyToken())

	output, err := reg.handler(invocation, input)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	outMsgs, err := dataSliceToMsgs(output)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encoding output: %v", err)
	}

	return &extensionpb.ExecuteResponse{Output: outMsgs}, nil
}

// Serve runs the calling process as an extension plugin. It blocks, handling
// gRPC requests from the host until the host disconnects. An extension's main()
// is typically just a call to Serve.
func Serve(register func(Registrar)) {
	handler := newServeHandler()
	register(handler)

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         pluginMap(handler),
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}

// configFromSnapshot rebuilds a configuration.Configuration on the plugin side
// from the string snapshot the host sent. Declared flags are added first so
// their defaults and types are honored; snapshot values then override.
func configFromSnapshot(snapshot map[string]string, flags *pflag.FlagSet) configuration.Configuration {
	config := configuration.NewWithOpts()
	if flags != nil {
		_ = config.AddFlagSet(flags)
	}
	for key, value := range snapshot {
		config.Set(key, value)
	}
	return config
}

func flagsToSpecs(flags *pflag.FlagSet) []*extensionpb.FlagSpec {
	if flags == nil {
		return nil
	}
	var specs []*extensionpb.FlagSpec
	flags.VisitAll(func(f *pflag.Flag) {
		specs = append(specs, &extensionpb.FlagSpec{
			Name:         f.Name,
			Type:         f.Value.Type(),
			DefaultValue: f.DefValue,
			Usage:        f.Usage,
		})
	})
	return specs
}

// specsToFlagSet rebuilds a pflag.FlagSet from discovered FlagSpecs so the host
// can register the workflow's configuration options with the engine.
func specsToFlagSet(name string, specs []*extensionpb.FlagSpec) *pflag.FlagSet {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	for _, spec := range specs {
		switch spec.GetType() {
		case "bool":
			fs.Bool(spec.GetName(), spec.GetDefaultValue() == "true", spec.GetUsage())
		case "int":
			def, _ := strconv.Atoi(spec.GetDefaultValue())
			fs.Int(spec.GetName(), def, spec.GetUsage())
		default:
			fs.String(spec.GetName(), spec.GetDefaultValue(), spec.GetUsage())
		}
	}
	return fs
}
