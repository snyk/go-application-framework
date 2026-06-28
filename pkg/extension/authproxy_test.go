package extension

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authInjectingTransport simulates the host's authenticated round tripper: it
// adds an Authorization header to every outbound request, exactly as the real
// NetworkAccess transport would.
type authInjectingTransport struct {
	token string
	base  http.RoundTripper
}

func (t *authInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "token "+t.token)
	return t.base.RoundTrip(req)
}

func TestAuthProxy_InjectsAuthAndForwards(t *testing.T) {
	// Fake upstream "Snyk API" records what it received.
	var gotAuth, gotPath, gotProxyToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotProxyToken = r.Header.Get(proxyTokenHeader)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	transport := &authInjectingTransport{token: "s3cr3t", base: http.DefaultTransport}
	proxy, err := NewAuthProxy(upstream.URL, transport, nil)
	require.NoError(t, err)
	defer proxy.Close()

	// A client that knows the secret reaches the upstream.
	req, _ := http.NewRequest(http.MethodGet, proxy.BaseURL()+"/rest/orgs", nil)
	req.Header.Set(proxyTokenHeader, proxy.Secret())
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "token s3cr3t", gotAuth, "host injected auth upstream")
	assert.Equal(t, "/rest/orgs", gotPath, "path forwarded to upstream")
	assert.Empty(t, gotProxyToken, "proxy secret must not leak upstream")
}

func TestAuthProxy_RejectsMissingOrWrongSecret(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()

	proxy, err := NewAuthProxy(upstream.URL, http.DefaultTransport, nil)
	require.NoError(t, err)
	defer proxy.Close()

	t.Run("missing secret", func(t *testing.T) {
		resp, err := http.Get(proxy.BaseURL() + "/rest/orgs")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("wrong secret", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, proxy.BaseURL()+"/rest/orgs", nil)
		req.Header.Set(proxyTokenHeader, "not-the-secret")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	assert.False(t, upstreamHit, "unauthorized requests must never reach upstream")
}

func TestNewAuthProxy_RejectsRelativeUpstream(t *testing.T) {
	_, err := NewAuthProxy("/not/absolute", http.DefaultTransport, nil)
	assert.Error(t, err)
}
