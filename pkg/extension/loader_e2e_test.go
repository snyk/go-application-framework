package extension

import (
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
