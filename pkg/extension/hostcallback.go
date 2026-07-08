package extension

import (
	"context"
	"fmt"
	"net/url"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// hostCallbackServer is the host side of the reverse channel. It is served, per
// invocation, on a go-plugin broker stream and is backed by that invocation's
// engine and analytics so sibling workflows run in the host's full context and
// analytics flow into the host's batch.
type hostCallbackServer struct {
	extensionpb.UnimplementedHostCallbackServer
	engine    workflow.Engine
	analytics analytics.Analytics
	config    configuration.Configuration
}

var _ extensionpb.HostCallbackServer = (*hostCallbackServer)(nil)

func newHostCallbackServer(engine workflow.Engine, analytics analytics.Analytics, config configuration.Configuration) *hostCallbackServer {
	return &hostCallbackServer{engine: engine, analytics: analytics, config: config}
}

func (s *hostCallbackServer) Invoke(_ context.Context, req *extensionpb.InvokeRequest) (*extensionpb.InvokeResponse, error) {
	if s.engine == nil {
		return nil, status.Error(codes.Unavailable, "engine not available")
	}

	id, err := url.Parse(req.GetIdentifier())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parsing identifier %q: %v", req.GetIdentifier(), err)
	}

	input, err := msgsToDataSlice(req.GetInput(), s.config)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decoding input: %v", err)
	}

	invokeOpts := []workflow.EngineInvokeOption{workflow.WithInput(input)}
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
