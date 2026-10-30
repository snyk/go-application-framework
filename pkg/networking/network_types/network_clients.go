package networktypes

import "net/http"

// NetworkClients is the part of networking.NetworkAccess that the scoper needs.
// It is declared here because pkg/networking imports pkg/auth, so pkg/auth cannot import it back.
type NetworkClients interface {
	// GetHttpClient returns the http client.
	GetHttpClient() *http.Client
	// GetUnauthorizedHttpClient returns an HTTP client that does not use authentication headers.
	GetUnauthorizedHttpClient() *http.Client
}
