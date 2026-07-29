package llm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitGatewayBaseURL(t *testing.T) {
	cases := []struct {
		in         string
		wantOrigin string
		wantPrefix string
	}{
		{"", "", ""},
		{"https://gw.example.com", "https://gw.example.com", ""},
		{"https://gw.example.com/vertex", "https://gw.example.com", "/vertex"},
		{"https://gw.example.com/vertex/", "https://gw.example.com", "/vertex"},
		{"https://gw.example.com:8443/g/anthropic", "https://gw.example.com:8443", "/g/anthropic"},
	}
	for _, tc := range cases {
		origin, prefix := splitGatewayBaseURL(tc.in)
		assert.Equal(t, tc.wantOrigin, origin, "origin for %q", tc.in)
		assert.Equal(t, tc.wantPrefix, prefix, "prefix for %q", tc.in)
	}
}

// vertexPathPrefixMiddleware re-adds the gateway prefix to whatever path the
// SDK's Vertex middleware produced (an absolute /v1/projects/… rawPredict path).
func TestVertexPathPrefixMiddleware(t *testing.T) {
	mw := vertexPathPrefixMiddleware("/vertex")
	req := httptest.NewRequest(http.MethodPost,
		"http://host/v1/projects/p/locations/l/publishers/anthropic/models/claude-x:rawPredict", nil)

	var gotPath string
	next := func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}
	_, err := mw(req, next)
	require.NoError(t, err)
	assert.Equal(t, "/vertex/v1/projects/p/locations/l/publishers/anthropic/models/claude-x:rawPredict", gotPath)
}
