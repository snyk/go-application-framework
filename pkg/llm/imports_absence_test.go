// Absence test: the LLM package must not pull the direct OpenAI Go SDK back
// into the dependency graph. All LLM access goes through langchaingo
// (github.com/tmc/langchaingo); this asserts openai-go never re-enters. Runs
// `go list -deps ./pkg/llm/...` from the module root and scans the graph.
//
// Why anthropic-sdk-go is NOT forbidden: langchaingo cannot reach Anthropic
// Claude models on Vertex AI Model Garden (served from :rawPredict with
// Anthropic's native Messages payload, not the Gemini :generateContent API that
// langchaingo's vertex wrapper and google.golang.org/genai speak). So the
// vertexModel Claude branch drives the official github.com/anthropics/
// anthropic-sdk-go directly — the same escape-hatch pattern used for
// Vertex-Gemini (genai) and Ollama (raw HTTP). The single mapping seam is
// preserved: the SDK is wrapped behind llms.Model / LangchainAdapter, so all
// callers stay vendor-neutral. openai-go stays forbidden — nothing needs it.
package llm_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoDirectVendorSDKImports(t *testing.T) {
	// anthropic-sdk-go is intentionally permitted — see the package comment
	// above for the Claude-on-Vertex justification.
	forbidden := []string{
		"github.com/openai/openai-go",
	}

	// Resolve the module root from this file's location so the test runs from
	// any working directory (go test sets cwd to the package).
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..")) // pkg/llm -> repo root

	cmd := exec.Command("go", "list", "-deps", "./pkg/llm/...")
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go list -deps failed: %s", string(out))

	for _, path := range forbidden {
		if strings.Contains(string(out), path) {
			t.Errorf("forbidden vendor SDK %q is still in the dependency graph; "+
				"all LLM access must go through github.com/tmc/langchaingo", path)
		}
	}
}
