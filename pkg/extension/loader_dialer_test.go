package extension

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

// TestGRPCDialer_ErrorsOnMissingBinary exercises the real dialer's failure path
// when the target path cannot be launched: it must return an error (and no
// connection) rather than panic or hang.
func TestGRPCDialer_ErrorsOnMissingBinary(t *testing.T) {
	logger := zerolog.Nop()
	dial := grpcDialer(&logger)

	conn, cleanup, err := dial(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Nil(t, cleanup)
}

// TestLoader_RealDialer_SkipsNonPluginBinary exercises the real go-plugin dialer
// against a binary that launches but is not an extension (handshake never
// completes). The loader must log-and-skip it and still initialize cleanly, with
// no workflow registered.
func TestLoader_RealDialer_SkipsNonPluginBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end plugin build in short mode")
	}

	binary := buildTestdataBinary(t, "notaplugin")

	loader := NewLoader(WithPaths(binary))
	t.Cleanup(loader.Close)

	engine := workflow.NewDefaultWorkFlowEngine()
	engine.AddExtensionInitializer(loader.Init)

	// A binary that fails the handshake must not abort engine initialization...
	require.NoError(t, engine.Init())
	// ...and must not register any workflow.
	assert.Empty(t, engine.GetWorkflows())
}

// buildTestdataBinary compiles a testdata command and returns its path.
func buildTestdataBinary(t *testing.T, name string) string {
	t.Helper()

	out := name
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	path := filepath.Join(t.TempDir(), out)

	cmd := exec.Command("go", "build", "-o", path,
		"github.com/snyk/go-application-framework/pkg/extension/testdata/"+name)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building testdata/%s: %v\n%s", name, err, output)
	}
	return path
}
