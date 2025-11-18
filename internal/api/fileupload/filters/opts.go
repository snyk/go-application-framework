package filters

import "net/http"

// Opt is a function that configures an deeproxyClient instance.
type Opt func(*DeeproxyClient)

// WithHTTPClient sets a custom HTTP client for the filters client.
func WithHTTPClient(httpClient *http.Client) Opt {
	return func(c *DeeproxyClient) {
		c.httpClient = httpClient
	}
}
