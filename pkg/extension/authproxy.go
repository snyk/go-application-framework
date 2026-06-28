package extension

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/rs/zerolog"
)

// proxyTokenHeader carries the per-invocation shared secret that authorizes a
// request to the loopback auth proxy. Only the extension subprocess is told the
// secret, so other local processes cannot use the proxy to make authenticated
// calls.
const proxyTokenHeader = "X-Snyk-Extension-Proxy-Token" //nolint:gosec // header name, not a credential

// AuthProxy is the host side of the "option C" network bridge. It is a loopback
// HTTP reverse proxy that forwards requests to a fixed upstream (the Snyk API)
// using the host's authenticated transport. The extension points a plain HTTP
// client at it, so the user's credentials are injected host-side and never
// cross into the extension process.
//
// The proxy is scoped to a single upstream by design: an extension can reach
// the configured API, not arbitrary hosts. Arbitrary-host egress would require
// a TLS-terminating forward proxy and is intentionally out of scope.
type AuthProxy struct {
	server   *http.Server
	listener net.Listener
	secret   string
	baseURL  string
}

// NewAuthProxy starts a loopback auth proxy forwarding to upstream via
// transport. transport is expected to be the host's authenticated
// http.RoundTripper (networking.NetworkAccess.GetRoundTripper), which injects
// authentication, default headers, proxy and TLS configuration.
func NewAuthProxy(upstream string, transport http.RoundTripper, logger *zerolog.Logger) (*AuthProxy, error) {
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream url %q: %w", upstream, err)
	}
	if upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		return nil, fmt.Errorf("upstream url %q must be absolute", upstream)
	}

	secret, err := randomSecret()
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("starting auth proxy listener: %w", err)
	}

	reverse := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstreamURL) // rewrites scheme+host, joins paths
			r.Out.Host = upstreamURL.Host
			r.Out.Header.Del(proxyTokenHeader) // never forward the secret upstream
		},
		Transport: transport,
	}

	proxy := &AuthProxy{
		server:   &http.Server{Handler: authGuard(secret, reverse)},
		listener: listener,
		secret:   secret,
		baseURL:  "http://" + listener.Addr().String(),
	}

	go func() {
		if serveErr := proxy.server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed && logger != nil {
			logger.Debug().Err(serveErr).Msg("auth proxy stopped")
		}
	}()

	return proxy, nil
}

// authGuard rejects requests that do not present the shared secret before
// handing them to the reverse proxy.
func authGuard(secret string, next http.Handler) http.Handler {
	want := []byte(secret)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get(proxyTokenHeader))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// BaseURL is the loopback base URL the extension should use as its API endpoint.
func (p *AuthProxy) BaseURL() string { return p.baseURL }

// Secret is the per-invocation token the extension must send via proxyTokenHeader.
func (p *AuthProxy) Secret() string { return p.secret }

// Close shuts the proxy down. It is safe to call once per proxy.
func (p *AuthProxy) Close() error {
	return p.server.Close()
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating proxy secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
