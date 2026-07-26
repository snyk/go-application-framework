package extension

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// buildExamplePlugin compiles the testdata extension into a temporary binary and
// returns its path. This is the real artifact the host loads at runtime.
func buildExamplePlugin(t *testing.T) string {
	t.Helper()

	name := "exampleplugin"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(t.TempDir(), name)

	// Build by import path so the command is module-aware regardless of cwd.
	cmd := exec.Command("go", "build", "-o", out,
		"github.com/snyk/go-application-framework/pkg/extension/testdata/exampleplugin")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building example plugin: %v\n%s", err, output)
	}
	return out
}

// TestEndToEnd_LoadRealPluginBinary is the load-without-rebuild proof: it
// compiles a standalone extension binary, then loads and invokes it through the
// real go-plugin subprocess dialer — no rebuild of the host required.
func TestEndToEnd_LoadRealPluginBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	binary := buildExamplePlugin(t)

	loader := NewLoader(WithPaths(binary))
	t.Cleanup(loader.Close)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())

	helloID, _ := url.Parse("flw://hello")
	entry, ok := engine.GetWorkflow(helloID)
	require.True(t, ok, "extension workflow should be registered from the binary")
	assert.True(t, entry.IsVisible())

	// Default flag value flows through to the subprocess.
	out, err := engine.Invoke(helloID)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("hello world"), out[0].GetPayload())
	assert.Equal(t, "text/plain", out[0].GetContentType())

	// A value set on the host config is exported to the subprocess.
	engine.GetConfiguration().Set("name", "snyk")
	out, err = engine.Invoke(helloID)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("hello snyk"), out[0].GetPayload())
}

// TestEndToEnd_ExtensionMakesAuthenticatedCall is the option-C proof: a loaded
// extension calls the "Snyk API" through the host's authenticated network
// access. The host injects the user's credentials; the extension process never
// holds them.
func TestEndToEnd_ExtensionMakesAuthenticatedCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	const token = "test-token-12345"

	// Fake Snyk API: records the Authorization header it received and echoes it.
	var seenAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		assert.Equal(t, "/echo", r.URL.Path)
		_, _ = w.Write([]byte(`{"authorization":"` + seenAuth + `"}`))
	}))
	defer upstream.Close()

	binary := buildExamplePlugin(t)

	loader := NewLoader(WithPaths(binary))
	t.Cleanup(loader.Close)

	engine := workflow.NewDefaultWorkFlowEngine()
	config := engine.GetConfiguration()
	config.Set(configuration.API_URL, upstream.URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())

	fetchID, _ := url.Parse("flw://hello.fetch")
	out, err := engine.Invoke(fetchID)
	require.NoError(t, err)
	require.Len(t, out, 1)

	// The host injected the token; the upstream saw it...
	assert.Contains(t, seenAuth, token, "host should have injected the auth token upstream")
	// ...and the authenticated response flowed back to the extension and out.
	payload, ok := out[0].GetPayload().([]byte)
	require.True(t, ok)
	assert.Contains(t, string(payload), token)
}

// TestEndToEnd_ExtensionCallsSiblingAndRecordsAnalytics is the host-callback
// proof: a loaded extension invokes a sibling workflow on the host engine and
// records analytics, both over the go-plugin broker, across a real subprocess.
func TestEndToEnd_ExtensionCallsSiblingAndRecordsAnalytics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	binary := buildExamplePlugin(t)

	loader := NewLoader(WithPaths(binary))
	t.Cleanup(loader.Close)

	engine := workflow.NewDefaultWorkFlowEngine()

	// Register a host-side sibling workflow the extension will invoke by id.
	engine.AddExtensionInitializer(func(e workflow.Engine) error {
		_, err := e.Register(
			workflow.NewWorkflowIdentifier("sibling"),
			workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("sibling", pflag.ContinueOnError)),
			func(_ workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
				payload := ""
				if len(input) > 0 {
					if b, ok := input[0].GetPayload().([]byte); ok {
						payload = string(b)
					}
				}
				outID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("sibling"), "result")
				return []workflow.Data{workflow.NewData(outID, "text/plain", []byte("sibling-got:"+payload))}, nil
			},
		)
		return err
	})
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())

	callID, _ := url.Parse("flw://hello.callsibling")
	out, err := engine.Invoke(callID)
	require.NoError(t, err)
	require.Len(t, out, 1)

	// The host ran the sibling with the extension's input and returned its output.
	payload, ok := out[0].GetPayload().([]byte)
	require.True(t, ok)
	assert.Equal(t, "sibling-got:from-extension", string(payload))

	// The extension's analytics reached the host's instrumentation, prefixed by
	// the calling workflow's identifier.
	obj, err := analytics.GetV2InstrumentationObject(engine.GetAnalytics().GetInstrumentation())
	require.NoError(t, err)
	require.NotNil(t, obj.Data.Attributes.Interaction.Extension)
	extension := *obj.Data.Attributes.Interaction.Extension
	assert.Equal(t, "ran", extension["hello.callsibling::ext.example"])
}

// TestEndToEnd_ConcurrentInvocations drives a single loaded extension with many
// concurrent invocations that each exercise a per-invocation resource: the
// option-C auth proxy (flw://hello.fetch) and the callback broker
// (flw://hello.callsibling). It verifies those per-invocation resources are
// isolated and race-free — run under `-race` for the strongest signal.
func TestEndToEnd_ConcurrentInvocations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	const token = "concurrent-token-abc"

	// Concurrency-safe fake API: each response is self-contained (echoes the
	// Authorization header it saw), so no shared server state is needed.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"authorization":"` + r.Header.Get("Authorization") + `"}`))
	}))
	defer upstream.Close()

	binary := buildExamplePlugin(t)
	loader := NewLoader(WithPaths(binary))
	t.Cleanup(loader.Close)

	engine := workflow.NewDefaultWorkFlowEngine()
	config := engine.GetConfiguration()
	config.Set(configuration.API_URL, upstream.URL)
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	engine.AddExtensionInitializer(func(e workflow.Engine) error {
		_, err := e.Register(
			workflow.NewWorkflowIdentifier("sibling"),
			workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("sibling", pflag.ContinueOnError)),
			func(_ workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
				payload := ""
				if len(input) > 0 {
					if b, ok := input[0].GetPayload().([]byte); ok {
						payload = string(b)
					}
				}
				outID := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("sibling"), "result")
				return []workflow.Data{workflow.NewData(outID, "text/plain", []byte("sibling-got:"+payload))}, nil
			},
		)
		return err
	})
	engine.AddExtensionInitializer(loader.Init)
	require.NoError(t, engine.Init())

	fetchID, _ := url.Parse("flw://hello.fetch")
	callID, _ := url.Parse("flw://hello.callsibling")

	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	payloads := make([]string, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fetchID
			if i%2 == 0 {
				id = callID
			}
			out, err := engine.Invoke(id)
			if err != nil {
				errs[i] = err
				return
			}
			if len(out) == 1 {
				if b, ok := out[0].GetPayload().([]byte); ok {
					payloads[i] = string(b)
				}
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoErrorf(t, errs[i], "invocation %d failed", i)
		if i%2 == 0 {
			assert.Equal(t, "sibling-got:from-extension", payloads[i], "sibling invoke %d", i)
		} else {
			assert.Contains(t, payloads[i], token, "authenticated fetch %d", i)
		}
	}
}
