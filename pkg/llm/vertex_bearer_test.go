package llm_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/llm"
)

// A Gemini Vertex call with an auth token must (1) authenticate via
// "Authorization: Bearer <token>" instead of ADC, and (2) preserve a base-URL
// path prefix (e.g. an internal gateway's /vertex) while the SDK appends the
// version + resource path. Reaching the httptest server at all proves ADC was
// skipped (no Google credentials exist in the test env).
func TestNewVertexAdapter_Gemini_BearerToken(t *testing.T) {
	var gotAuth, gotPath, gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUser = r.Header.Get("x-user-id")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	}))
	defer srv.Close()

	a, err := llm.NewVertexAdapter("gemini-2.5-flash", "my-proj", "us-central1", srv.URL+"/vertex", "gw-token-abc",
		http.Header{"x-user-id": {"jsmith"}}, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "gemini-2.5-flash",
		MaxTokens: 16,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
	})
	require.NoError(t, err)

	assert.Equal(t, "Bearer gw-token-abc", gotAuth, "must send the bearer token, not ADC")
	assert.Equal(t, "jsmith", gotUser, "extra gateway header must be sent")
	assert.Equal(t, "/vertex/v1beta1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent", gotPath,
		"base-URL prefix preserved and full Vertex resource path appended")
}

// A Claude-on-Vertex call with an auth token must rewrite to the Vertex
// rawPredict form while preserving a gateway path prefix (/vertex), send the
// bearer token, and apply the Vertex body tweaks (inject anthropic_version,
// move model out of the body into the URL). Reaching the server proves ADC was
// skipped.
func TestNewVertexAdapter_Claude_BearerToken_RawPredict(t *testing.T) {
	var gotAuth, gotPath, gotUser string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUser = r.Header.Get("x-user-id")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","type":"message","role":"assistant","model":"claude","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	a, err := llm.NewVertexAdapter("claude-3-7-sonnet@20240229", "my-proj", "us-east5", srv.URL+"/vertex", "gw-token-abc",
		http.Header{"x-user-id": {"jsmith"}}, nil)
	require.NoError(t, err)

	_, err = a.ChatCompletion(ctx(), &llm.ChatRequest{
		Model:     "claude-3-7-sonnet@20240229",
		MaxTokens: 16,
		Messages:  []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
	})
	require.NoError(t, err)

	assert.Equal(t, "Bearer gw-token-abc", gotAuth)
	assert.Equal(t, "jsmith", gotUser, "extra gateway header must be sent")
	assert.Equal(t, "/vertex/v1/projects/my-proj/locations/us-east5/publishers/anthropic/models/claude-3-7-sonnet@20240229:rawPredict", gotPath,
		"rawPredict path under the gateway /vertex prefix")
	assert.Equal(t, "vertex-2023-10-16", gotBody["anthropic_version"], "anthropic_version must be injected")
	_, hasModel := gotBody["model"]
	assert.False(t, hasModel, "model must be moved from body into the URL")
}
