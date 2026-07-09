package extension

import (
	"context"
	"net/url"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// fakeConn is an in-memory pluginConn used to test the Loader's registration
// and proxying logic without launching a subprocess.
type fakeConn struct {
	specs        []*extensionpb.WorkflowSpec
	output       []*extensionpb.DataMsg
	execErr      error
	lastReq      executeRequest
	executeCalls int
}

func (f *fakeConn) Discover(context.Context) ([]*extensionpb.WorkflowSpec, error) {
	return f.specs, nil
}

func (f *fakeConn) Execute(_ context.Context, req executeRequest) ([]*extensionpb.DataMsg, error) {
	f.executeCalls++
	f.lastReq = req
	if f.execErr != nil {
		return nil, f.execErr
	}
	return f.output, nil
}

func fakeDialer(conn pluginConn) dialer {
	return func(context.Context, string) (pluginConn, func(), error) {
		return conn, func() {}, nil
	}
}

func newInitializedEngine(t *testing.T, loader *Loader) workflow.Engine {
	t.Helper()
	engine := workflow.NewDefaultWorkFlowEngine()
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())
	return engine
}

func TestLoader_RegistersDiscoveredWorkflows(t *testing.T) {
	conn := &fakeConn{
		specs: []*extensionpb.WorkflowSpec{
			{Identifier: "flw://hello", Visible: true, Flags: []*extensionpb.FlagSpec{
				{Name: "name", Type: "string", DefaultValue: "world", Usage: "who to greet"},
			}},
			{Identifier: "flw://secret", Visible: false},
		},
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)))
	engine := newInitializedEngine(t, loader)

	helloID, _ := url.Parse("flw://hello")
	entry, ok := engine.GetWorkflow(helloID)
	require.True(t, ok, "hello workflow should be registered")
	assert.True(t, entry.IsVisible())

	secretID, _ := url.Parse("flw://secret")
	secretEntry, ok := engine.GetWorkflow(secretID)
	require.True(t, ok)
	assert.False(t, secretEntry.IsVisible(), "hidden workflow visibility should be honored")

	// The declared flag is wired into the engine's configuration.
	assert.Equal(t, "world", engine.GetConfiguration().GetString("name"))
}

func TestLoader_ProxyInvocation(t *testing.T) {
	outID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
	conn := &fakeConn{
		specs: []*extensionpb.WorkflowSpec{
			{Identifier: "flw://hello", Visible: true, Flags: []*extensionpb.FlagSpec{
				{Name: "name", Type: "string", DefaultValue: "world"},
			}},
		},
		output: []*extensionpb.DataMsg{
			mustMsg(t, workflow.NewData(outID, "text/plain", []byte("hi"))),
		},
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)))
	engine := newInitializedEngine(t, loader)

	engine.GetConfiguration().Set("name", "snyk")

	helloID, _ := url.Parse("flw://hello")
	output, err := engine.Invoke(helloID)
	require.NoError(t, err)

	// The proxy forwarded the call to the extension...
	assert.Equal(t, 1, conn.executeCalls)
	assert.Equal(t, "flw://hello", conn.lastReq.identifier)
	// ...exporting only the declared config key, with its live value.
	assert.Equal(t, map[string]string{"name": "snyk"}, conn.lastReq.config)
	// ...and the extension's output came back converted to workflow.Data.
	require.Len(t, output, 1)
	assert.Equal(t, []byte("hi"), output[0].GetPayload())
}

func TestLoader_FailingDialerDoesNotAbortInit(t *testing.T) {
	loader := NewLoader(WithPaths("broken"), withDialer(func(context.Context, string) (pluginConn, func(), error) {
		return nil, nil, assert.AnError
	}))

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.AddExtensionInitializer(loader.Init)
	// A broken extension must not break engine initialization.
	assert.NoError(t, engine.Init())
}

func TestLoader_DoesNotOverrideExistingWorkflowByDefault(t *testing.T) {
	// A workflow already registered on the engine (e.g. a bundled extension).
	bundledID := workflow.NewWorkflowIdentifier("hello")
	engine := workflow.NewDefaultWorkFlowEngine()
	_, err := engine.Register(
		bundledID,
		workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("hello", pflag.ContinueOnError)),
		func(_ workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			id := workflow.NewTypeIdentifier(bundledID, "result")
			return []workflow.Data{workflow.NewData(id, "text/plain", []byte("bundled"))}, nil
		},
	)
	require.NoError(t, err)

	// A dynamic extension that also provides flw://hello.
	conn := &fakeConn{
		specs:  []*extensionpb.WorkflowSpec{{Identifier: "flw://hello", Visible: true}},
		output: []*extensionpb.DataMsg{mustMsg(t, workflow.NewData(workflow.NewTypeIdentifier(bundledID, "result"), "text/plain", []byte("extension")))},
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)))
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())

	// The bundled workflow must remain; the extension's must be skipped.
	out, err := engine.Invoke(bundledID)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("bundled"), out[0].GetPayload())
	assert.Equal(t, 0, conn.executeCalls, "the bundled callback should run, not the extension proxy")
}

func TestLoader_OverridesExistingWorkflowWhenAllowed(t *testing.T) {
	bundledID := workflow.NewWorkflowIdentifier("hello")
	engine := workflow.NewDefaultWorkFlowEngine()
	_, err := engine.Register(
		bundledID,
		workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("hello", pflag.ContinueOnError)),
		func(_ workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			return nil, nil
		},
	)
	require.NoError(t, err)

	conn := &fakeConn{
		specs:  []*extensionpb.WorkflowSpec{{Identifier: "flw://hello", Visible: true}},
		output: []*extensionpb.DataMsg{mustMsg(t, workflow.NewData(workflow.NewTypeIdentifier(bundledID, "result"), "text/plain", []byte("extension")))},
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)), WithAllowOverride(true))
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())

	// With override enabled, the extension's proxy replaces the bundled callback.
	out, err := engine.Invoke(bundledID)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("extension"), out[0].GetPayload())
	assert.Equal(t, 1, conn.executeCalls)
}

func TestLoader_DoesNotExportSensitiveConfigValue(t *testing.T) {
	conn := &fakeConn{
		specs: []*extensionpb.WorkflowSpec{
			{Identifier: "flw://hello", Visible: true, Flags: []*extensionpb.FlagSpec{
				// A flag colliding with a real host credential key, and one
				// that doesn't, to prove only the collision is blocked.
				{Name: "snyk_token", Type: "string"},
				{Name: "name", Type: "string", DefaultValue: "world"},
			}},
		},
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)))
	engine := newInitializedEngine(t, loader)
	engine.GetConfiguration().Set("snyk_token", "super-secret")
	engine.GetConfiguration().Set("name", "snyk")

	helloID, _ := url.Parse("flw://hello")
	_, err := engine.Invoke(helloID)
	require.NoError(t, err)

	assert.NotContains(t, conn.lastReq.config, "snyk_token", "a flag colliding with a reserved credential key must never be exported")
	assert.Equal(t, "snyk", conn.lastReq.config["name"], "non-colliding flags still export normally")
}

func TestLoader_InitErrorsAfterClose(t *testing.T) {
	conn := &fakeConn{
		specs: []*extensionpb.WorkflowSpec{{Identifier: "flw://hello", Visible: true}},
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)))
	engine := workflow.NewDefaultWorkFlowEngine()
	require.NoError(t, loader.Init(engine))

	loader.Close()

	err := loader.Init(engine)
	require.Error(t, err, "a closed Loader must not silently re-init: it would leave proxy workflows pointing at killed processes")
}

func TestLoader_ProxyPropagatesExecuteError(t *testing.T) {
	conn := &fakeConn{
		specs:   []*extensionpb.WorkflowSpec{{Identifier: "flw://hello", Visible: true}},
		execErr: assert.AnError,
	}
	loader := NewLoader(WithPaths("fake"), withDialer(fakeDialer(conn)))
	engine := newInitializedEngine(t, loader)

	helloID, _ := url.Parse("flw://hello")
	_, err := engine.Invoke(helloID)
	require.Error(t, err)
}
