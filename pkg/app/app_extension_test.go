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
