package extension

import (
	"context"
	"testing"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// newTestConn wires a serveHandler (the plugin side) to a grpcClient (the host
// side) over a real in-memory gRPC connection, exercising the full adapter +
// conversion stack without spawning a subprocess.
func newTestConn(t *testing.T, register func(Registrar)) pluginConn {
	t.Helper()
	handler := newServeHandler()
	register(handler)

	conn, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		extensionpb.RegisterExtensionServer(s, handler)
	})
	t.Cleanup(func() { _ = conn.Close() })

	return &grpcClient{client: extensionpb.NewExtensionClient(conn)}
}

func TestGRPC_Discover(t *testing.T) {
	conn := newTestConn(t, func(r Registrar) {
		flags := pflag.NewFlagSet("hello", pflag.ContinueOnError)
		flags.String("name", "world", "who to greet")
		r.Register("flw://hello", noopHandler, WithFlags(flags))
		r.Register("flw://internal", noopHandler, Hidden())
	})

	specs, err := conn.Discover(context.Background())
	require.NoError(t, err)
	require.Len(t, specs, 2)

	assert.Equal(t, "flw://hello", specs[0].GetIdentifier())
	assert.True(t, specs[0].GetVisible())
	require.Len(t, specs[0].GetFlags(), 1)
	assert.Equal(t, "name", specs[0].GetFlags()[0].GetName())
	assert.Equal(t, "world", specs[0].GetFlags()[0].GetDefaultValue())

	assert.Equal(t, "flw://internal", specs[1].GetIdentifier())
	assert.False(t, specs[1].GetVisible())
}

func TestGRPC_Execute_RoundTrip(t *testing.T) {
	// A handler that greets using the "name" config value and echoes its input.
	handler := func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
		id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
		greeting := "hello " + invocation.GetConfiguration().GetString("name")
		out := workflow.NewData(id, "text/plain", []byte(greeting))
		result := []workflow.Data{out}
		return append(result, input...), nil
	}

	conn := newTestConn(t, func(r Registrar) {
		flags := pflag.NewFlagSet("hello", pflag.ContinueOnError)
		flags.String("name", "world", "who to greet")
		r.Register("flw://hello", handler, WithFlags(flags))
	})

	inID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "echo")
	input := []*extensionpb.DataMsg{mustMsg(t, workflow.NewData(inID, "text/plain", []byte("ping")))}

	out, err := conn.Execute(context.Background(), executeRequest{
		identifier: "flw://hello",
		config:     map[string]string{"name": "snyk"},
		input:      input,
	})
	require.NoError(t, err)
	require.Len(t, out, 2)

	// The config value the host exported reached the handler.
	assert.Equal(t, []byte("hello snyk"), out[0].GetPayload())
	assert.Equal(t, "text/plain", out[0].GetMetadata()[workflow.Content_type_key])
	// The input was echoed back across the boundary.
	assert.Equal(t, []byte("ping"), out[1].GetPayload())
}

func TestGRPC_Execute_UnknownWorkflow(t *testing.T) {
	conn := newTestConn(t, func(r Registrar) {
		r.Register("flw://hello", noopHandler)
	})

	_, err := conn.Execute(context.Background(), executeRequest{identifier: "flw://missing"})
	assert.Error(t, err)
}

func TestGRPC_Execute_HandlerError(t *testing.T) {
	conn := newTestConn(t, func(r Registrar) {
		r.Register("flw://boom", func(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
			return nil, assert.AnError
		})
	})

	_, err := conn.Execute(context.Background(), executeRequest{identifier: "flw://boom"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), assert.AnError.Error())
}

func TestServeHandler_Execute_ForwardsRuntimeInfo(t *testing.T) {
	var gotName, gotVersion string
	handler := newServeHandler()
	handler.Register("flw://hello", func(invocation workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		ri := invocation.GetRuntimeInfo()
		require.NotNil(t, ri)
		gotName = ri.GetName()
		gotVersion = ri.GetVersion()
		return nil, nil
	})

	_, err := handler.Execute(context.Background(), &extensionpb.ExecuteRequest{
		Identifier:         "flw://hello",
		RuntimeInfoName:    "snyk-cli",
		RuntimeInfoVersion: "1.2.3",
	})
	require.NoError(t, err)
	assert.Equal(t, "snyk-cli", gotName)
	assert.Equal(t, "1.2.3", gotVersion)
}

func noopHandler(workflow.InvocationContext, []workflow.Data) ([]workflow.Data, error) {
	return nil, nil
}

func mustMsg(t *testing.T, d workflow.Data) *extensionpb.DataMsg {
	t.Helper()
	msg, err := dataToMsg(d)
	require.NoError(t, err)
	return msg
}
