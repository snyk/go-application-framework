package extension

import (
	"context"
	"fmt"
	"net/url"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// invocationDepthKey is the context key an invocation's round-trip depth
// through HostCallback.Invoke is stored under. Each hop from host to
// extension and back increments it; hostCallbackServer.Invoke rejects the
// call once it exceeds maxInvocationDepth. This bounds a self-referential (or
// mutually recursive) extension invocation chain to a fixed number of
// subprocess/goroutine/listener round trips instead of letting it run until
// the host exhausts file descriptors or memory -- a failure mode an
// in-process workflow call stack would instead hit as an ordinary (bounded)
// stack overflow.
type invocationDepthKey struct{}

const maxInvocationDepth = 10

func invocationDepth(ctx context.Context) int {
	if d, ok := ctx.Value(invocationDepthKey{}).(int); ok {
		return d
	}
	return 0
}

func withInvocationDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, invocationDepthKey{}, depth)
}

// recoveryInterceptor turns a panic inside a HostCallback handler -- most
// notably a host workflow, invoked with plugin-supplied input, that panics --
// into a gRPC error instead of crashing the host process.
func recoveryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "panic in %s: %v", info.FullMethod, r)
		}
	}()
	return handler(ctx, req)
}

// hostCallbackServer is the host side of the reverse channel. It is served, per
// invocation, on a go-plugin broker stream and is backed by that invocation's
// engine and analytics so sibling workflows run in the host's full context and
// analytics flow into the host's batch.
type hostCallbackServer struct {
	extensionpb.UnimplementedHostCallbackServer
	engine    workflow.Engine
	analytics analytics.Analytics
	config    configuration.Configuration
	depth     int
}

var _ extensionpb.HostCallbackServer = (*hostCallbackServer)(nil)

func newHostCallbackServer(engine workflow.Engine, analytics analytics.Analytics, config configuration.Configuration, depth int) *hostCallbackServer {
	return &hostCallbackServer{engine: engine, analytics: analytics, config: config, depth: depth}
}

func (s *hostCallbackServer) Invoke(ctx context.Context, req *extensionpb.InvokeRequest) (*extensionpb.InvokeResponse, error) {
	if s.engine == nil {
		return nil, status.Error(codes.Unavailable, "engine not available")
	}

	nextDepth := s.depth + 1
	if nextDepth > maxInvocationDepth {
		return nil, status.Errorf(codes.ResourceExhausted, "invocation depth exceeded (%d): likely a self-referential extension invocation", maxInvocationDepth)
	}

	id, err := url.Parse(req.GetIdentifier())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing identifier %q: %v", req.GetIdentifier(), err)
	}

	input, err := msgsToDataSlice(req.GetInput(), s.config)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decoding input: %v", err)
	}

	invokeOpts := []workflow.EngineInvokeOption{
		workflow.WithInput(input),
		workflow.WithContext(withInvocationDepth(ctx, nextDepth)),
	}
	if overrides := req.GetConfig(); len(overrides) > 0 && s.config != nil {
		cfg := s.config.Clone()
		for key, value := range overrides {
			cfg.Set(key, value)
		}
		invokeOpts = append(invokeOpts, workflow.WithConfig(cfg))
	}

	output, err := s.engine.Invoke(id, invokeOpts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invoking %q: %v", req.GetIdentifier(), err)
	}

	outMsgs, err := dataSliceToMsgs(output)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encoding output: %v", err)
	}
	return &extensionpb.InvokeResponse{Output: outMsgs}, nil
}

func (s *hostCallbackServer) AddExtensionValue(_ context.Context, req *extensionpb.ExtensionValue) (*extensionpb.CallbackAck, error) {
	if s.analytics != nil {
		switch req.GetValue().(type) {
		case *extensionpb.ExtensionValue_StringValue:
			s.analytics.AddExtensionStringValue(req.GetKey(), req.GetStringValue())
		case *extensionpb.ExtensionValue_IntValue:
			s.analytics.AddExtensionIntegerValue(req.GetKey(), int(req.GetIntValue()))
		case *extensionpb.ExtensionValue_BoolValue:
			s.analytics.AddExtensionBoolValue(req.GetKey(), req.GetBoolValue())
		}
	}
	return &extensionpb.CallbackAck{}, nil
}

func (s *hostCallbackServer) ReportError(_ context.Context, req *extensionpb.ReportErrorRequest) (*extensionpb.CallbackAck, error) {
	if s.analytics != nil {
		s.analytics.AddError(fmt.Errorf("%s", req.GetMessage()))
	}
	return &extensionpb.CallbackAck{}, nil
}
