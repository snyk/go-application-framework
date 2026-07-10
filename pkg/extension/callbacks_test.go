package extension

import (
	"context"
	"errors"
	"testing"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// recordingAnalytics captures the extension-facing recording calls while
// delegating everything else to a real analytics instance.
type recordingAnalytics struct {
	analytics.Analytics
	strings map[string]string
	ints    map[string]int
	bools   map[string]bool
	errs    []error
}

func newRecordingAnalytics() *recordingAnalytics {
	return &recordingAnalytics{
		Analytics: analytics.New(),
		strings:   map[string]string{},
		ints:      map[string]int{},
		bools:     map[string]bool{},
	}
}

func (r *recordingAnalytics) AddExtensionStringValue(k, v string) { r.strings[k] = v }
func (r *recordingAnalytics) AddExtensionIntegerValue(k string, v int) {
	r.ints[k] = v
}
func (r *recordingAnalytics) AddExtensionBoolValue(k string, v bool) { r.bools[k] = v }
func (r *recordingAnalytics) AddError(err error)                     { r.errs = append(r.errs, err) }

// hostWithSibling builds an initialized host engine exposing a "flw://sibling"
// workflow that prefixes its input, plus a recording analytics, and serves them
// over an in-memory HostCallback connection.
func hostWithSibling(t *testing.T) (extensionpb.HostCallbackClient, *recordingAnalytics) {
	t.Helper()

	engine := workflow.NewDefaultWorkFlowEngine()
	siblingID := workflow.NewWorkflowIdentifier("sibling")
	_, err := engine.Register(
		siblingID,
		workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("sibling", pflag.ContinueOnError)),
		func(_ workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
			payload := ""
			if len(input) > 0 {
				if b, ok := input[0].GetPayload().([]byte); ok {
					payload = string(b)
				}
			}
			outID := workflow.NewTypeIdentifier(siblingID, "result")
			return []workflow.Data{workflow.NewData(outID, "text/plain", []byte("sibling:"+payload))}, nil
		},
	)
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	rec := newRecordingAnalytics()
	server := newHostCallbackServer(engine, rec, engine.GetConfiguration(), 0)

	conn, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		extensionpb.RegisterHostCallbackServer(s, server)
	})
	t.Cleanup(func() { _ = conn.Close() })

	return extensionpb.NewHostCallbackClient(conn), rec
}

func TestRemoteEngine_InvokesSibling(t *testing.T) {
	client, _ := hostWithSibling(t)
	engine := &remoteEngine{ctx: context.Background(), client: client, config: configuration.New()}

	inID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("caller"), "data")
	out, err := engine.Invoke(
		workflow.NewWorkflowIdentifier("sibling"),
		workflow.WithInput([]workflow.Data{workflow.NewData(inID, "text/plain", []byte("ping"))}),
	)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("sibling:ping"), out[0].GetPayload())
}

func TestRemoteEngine_InvokeForwardsConfigOverrides(t *testing.T) {
	engine := workflow.NewDefaultWorkFlowEngine()
	siblingID := workflow.NewWorkflowIdentifier("sibling")
	siblingFlags := pflag.NewFlagSet("sibling", pflag.ContinueOnError)
	siblingFlags.String("greeting", "", "")
	_, err := engine.Register(
		siblingID,
		workflow.ConfigurationOptionsFromFlagset(siblingFlags),
		func(invocation workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			greeting := invocation.GetConfiguration().GetString("greeting")
			outID := workflow.NewTypeIdentifier(siblingID, "result")
			return []workflow.Data{workflow.NewData(outID, "text/plain", []byte(greeting))}, nil
		},
	)
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	server := newHostCallbackServer(engine, newRecordingAnalytics(), engine.GetConfiguration(), 0)
	conn, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		extensionpb.RegisterHostCallbackServer(s, server)
	})
	t.Cleanup(func() { _ = conn.Close() })

	baseConfig := configuration.New()
	remote := &remoteEngine{ctx: context.Background(), client: extensionpb.NewHostCallbackClient(conn), config: baseConfig}

	override := baseConfig.Clone()
	override.Set("greeting", "hello-from-extension")

	out, err := remote.Invoke(siblingID, workflow.WithConfig(override))
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("hello-from-extension"), out[0].GetPayload())
}

func TestRemoteEngine_InvokeForwardsInPlaceConfigMutation(t *testing.T) {
	engine := workflow.NewDefaultWorkFlowEngine()
	siblingID := workflow.NewWorkflowIdentifier("sibling")
	siblingFlags := pflag.NewFlagSet("sibling", pflag.ContinueOnError)
	siblingFlags.String("greeting", "", "")
	_, err := engine.Register(
		siblingID,
		workflow.ConfigurationOptionsFromFlagset(siblingFlags),
		func(invocation workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			greeting := invocation.GetConfiguration().GetString("greeting")
			outID := workflow.NewTypeIdentifier(siblingID, "result")
			return []workflow.Data{workflow.NewData(outID, "text/plain", []byte(greeting))}, nil
		},
	)
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	server := newHostCallbackServer(engine, newRecordingAnalytics(), engine.GetConfiguration(), 0)
	conn, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		extensionpb.RegisterHostCallbackServer(s, server)
	})
	t.Cleanup(func() { _ = conn.Close() })

	// Mirrors an extension's own invocation.GetConfiguration(): the object a
	// handler mutates in place, rather than a distinct clone built for
	// WithConfig.
	handlerConfig := configuration.New()
	remote := &remoteEngine{
		ctx:        context.Background(),
		client:     extensionpb.NewHostCallbackClient(conn),
		config:     handlerConfig,
		baseConfig: configSnapshot(handlerConfig),
	}

	// The handler mutates its own config object in place -- the same pointer
	// remote.config already holds -- then invokes with that same object.
	handlerConfig.Set("greeting", "mutated-in-place")

	out, err := remote.Invoke(siblingID, workflow.WithConfig(handlerConfig))
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("mutated-in-place"), out[0].GetPayload(), "an in-place mutation of the handler's own config object must still be forwarded")
}

func TestRemoteEngine_GetRuntimeInfo_ReturnsForwardedInfo(t *testing.T) {
	ri := runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.2.3"))
	remote := &remoteEngine{runtimeInfo: ri}

	got := remote.GetRuntimeInfo()
	require.NotNil(t, got)
	assert.Equal(t, "snyk-cli", got.GetName())
	assert.Equal(t, "1.2.3", got.GetVersion())
}

func TestConfigOverrides_SkipsSliceTypedValues(t *testing.T) {
	baseline := map[string]string{}
	override := configuration.New()
	override.Set("subdomains", []string{"a.example.com", "b.example.com"})
	override.Set("greeting", "hi")

	diffs := configOverrides(baseline, override)

	assert.NotContains(t, diffs, "subdomains", "a slice-typed value must not be forwarded as a stringified scalar")
	assert.Equal(t, "hi", diffs["greeting"])
}

func TestConfigOverrides_DetectsBoolAndIntChanges(t *testing.T) {
	base := configuration.New()
	base.Set("verbose", false)
	base.Set("retries", 0)
	baseline := configSnapshot(base)

	override := base.Clone()
	override.Set("verbose", true)
	override.Set("retries", 5)

	diffs := configOverrides(baseline, override)

	// GetString silently returns "" for bool/int values, which would make
	// false-vs-true and 0-vs-5 look identical (and therefore unchanged) if the
	// diff were computed with it.
	assert.Equal(t, "true", diffs["verbose"])
	assert.Equal(t, "5", diffs["retries"])
}

func TestHostCallbackServer_RejectsConfigOverrideForUndeclaredKey(t *testing.T) {
	engine := workflow.NewDefaultWorkFlowEngine()
	engine.GetConfiguration().Set(configuration.API_URL, "https://real-snyk-api.example")

	siblingID := workflow.NewWorkflowIdentifier("sibling")
	var observedAPIURL string
	_, err := engine.Register(
		siblingID,
		// Declares no flags of its own -- in particular, does not declare
		// configuration.API_URL as configurable.
		workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("sibling", pflag.ContinueOnError)),
		func(invocation workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			observedAPIURL = invocation.GetConfiguration().GetString(configuration.API_URL)
			return nil, nil
		},
	)
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	server := newHostCallbackServer(engine, newRecordingAnalytics(), engine.GetConfiguration(), 0)
	conn, _ := plugin.TestGRPCConn(t, func(s *grpc.Server) {
		extensionpb.RegisterHostCallbackServer(s, server)
	})
	t.Cleanup(func() { _ = conn.Close() })

	client := extensionpb.NewHostCallbackClient(conn)
	_, err = client.Invoke(context.Background(), &extensionpb.InvokeRequest{
		Identifier: siblingID.String(),
		// An extension trying to redirect where the host attaches the real
		// credential: ShouldRequireAuthentication matches a request's URL
		// against exactly this key.
		Config: map[string]string{configuration.API_URL: "https://attacker.example"},
	})
	require.NoError(t, err)

	assert.Equal(t, "https://real-snyk-api.example", observedAPIURL,
		"a config override for a key the invoked workflow never declared must be refused, not applied to the clone of the host's real configuration")
}

func TestHostCallbackServer_RejectsInvocationBeyondMaxDepth(t *testing.T) {
	engine := workflow.NewDefaultWorkFlowEngine()
	require.NoError(t, engine.Init())

	server := newHostCallbackServer(engine, newRecordingAnalytics(), engine.GetConfiguration(), maxInvocationDepth)

	_, err := server.Invoke(context.Background(), &extensionpb.InvokeRequest{Identifier: "flw://sibling"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invocation depth exceeded")
}

func TestRecoveryInterceptor_RecoversPanic(t *testing.T) {
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic("boom")
	}

	_, err := recoveryInterceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/HostCallback/Invoke"}, handler)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestRemoteEngine_InvokeUnknownSiblingErrors(t *testing.T) {
	client, _ := hostWithSibling(t)
	engine := &remoteEngine{ctx: context.Background(), client: client, config: configuration.New()}

	_, err := engine.Invoke(workflow.NewWorkflowIdentifier("does-not-exist"))
	assert.Error(t, err)
}

func TestRemoteAnalytics_ForwardsToHost(t *testing.T) {
	client, rec := hostWithSibling(t)
	stats := newRemoteAnalytics(context.Background(), client)

	stats.AddExtensionStringValue("ext.name", "demo")
	stats.AddExtensionIntegerValue("ext.count", 7)
	stats.AddExtensionBoolValue("ext.enabled", true)
	stats.AddError(errors.New("boom"))

	assert.Equal(t, "demo", rec.strings["ext.name"])
	assert.Equal(t, 7, rec.ints["ext.count"])
	assert.Equal(t, true, rec.bools["ext.enabled"])
	require.Len(t, rec.errs, 1)
	assert.Contains(t, rec.errs[0].Error(), "boom")
}
