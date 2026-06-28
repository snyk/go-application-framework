package extension

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
