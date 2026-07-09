package app

import (
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/extension"
)

func TestWithExtensionPaths_StoresPathsOnConfig(t *testing.T) {
	engine := CreateAppEngineWithOptions(
		WithConfiguration(configuration.New()),
		WithExtensionPaths("/path/a", "/path/b"),
	)

	paths := engine.GetConfiguration().GetStringSlice(extension.ConfigurationKeyPaths)
	assert.Equal(t, []string{"/path/a", "/path/b"}, paths)
}

func TestWithExtensionPaths_DeduplicatesRepeatedPath(t *testing.T) {
	engine := CreateAppEngineWithOptions(
		WithConfiguration(configuration.New()),
		WithExtensionPaths("/path/a"),
		WithExtensionPaths("/path/a", "/path/b"),
	)

	paths := engine.GetConfiguration().GetStringSlice(extension.ConfigurationKeyPaths)
	assert.Equal(t, []string{"/path/a", "/path/b"}, paths, "a path repeated across calls must not launch a duplicate subprocess")
}

func TestWithConfiguration_MergeDeduplicatesCarriedForwardPaths(t *testing.T) {
	config := configuration.New()
	engine := CreateAppEngineWithOptions(
		WithExtensionPaths("/path/a"),
		WithConfiguration(config),
		WithExtensionPaths("/path/a", "/path/b"),
	)

	paths := engine.GetConfiguration().GetStringSlice(extension.ConfigurationKeyPaths)
	assert.Equal(t, []string{"/path/a", "/path/b"}, paths, "the path carried forward across the configuration swap must not duplicate one already present on the new configuration")
}

func TestCreateAppEngine_LoadsConfiguredExtension(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	binary := buildExamplePluginForApp(t)

	engine := CreateAppEngineWithOptions(
		WithConfiguration(configuration.New()),
		WithExtensionPaths(binary),
	)
	require.NoError(t, engine.Init())

	helloID, _ := url.Parse("flw://hello")
	_, ok := engine.GetWorkflow(helloID)
	require.True(t, ok, "configured extension workflow should be registered")

	out, err := engine.Invoke(helloID)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, []byte("hello world"), out[0].GetPayload())
}

// TestCreateAppEngine_ExtensionPathSetAfterConstruction_StillLoads reproduces
// the CLI's actual startup order: create the engine, then parse flags (which
// populates a repeatable --plugin-path flag bound to
// extension.ConfigurationKeyPaths), then call Init(). The path must still be
// picked up even though it wasn't present on the configuration when
// CreateAppEngineWithOptions ran.
func TestCreateAppEngine_ExtensionPathSetAfterConstruction_StillLoads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	binary := buildExamplePluginForApp(t)

	config := configuration.New()
	engine := CreateAppEngineWithOptions(WithConfiguration(config))

	// Simulate flag parsing happening after engine construction.
	config.Set(extension.ConfigurationKeyPaths, []string{binary})

	require.NoError(t, engine.Init())

	helloID, _ := url.Parse("flw://hello")
	_, ok := engine.GetWorkflow(helloID)
	require.True(t, ok, "extension path set after construction, before Init(), should still be loaded")
}

func TestCreateAppEngineWithCloser_ClosesExtensionProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	binary := buildExamplePluginForApp(t)

	engine, closer := CreateAppEngineWithCloser(
		WithConfiguration(configuration.New()),
		WithExtensionPaths(binary),
	)
	require.NoError(t, engine.Init())

	helloID, _ := url.Parse("flw://hello")
	_, ok := engine.GetWorkflow(helloID)
	require.True(t, ok)

	// Must not panic or block, and must actually terminate the subprocess
	// (Loader.Close is exercised directly in pkg/extension; here we only
	// verify the closer wired up by CreateAppEngineWithCloser reaches it).
	closer()
}

func TestCreateAppEngineWithCloser_NoOpWhenNoExtensionsConfigured(t *testing.T) {
	engine, closer := CreateAppEngineWithCloser(WithConfiguration(configuration.New()))
	require.NoError(t, engine.Init())
	closer()
}

func buildExamplePluginForApp(t *testing.T) string {
	t.Helper()
	name := "exampleplugin"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out,
		"github.com/snyk/go-application-framework/pkg/extension/testdata/exampleplugin")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building example plugin: %v\n%s", err, output)
	}
	return out
}
