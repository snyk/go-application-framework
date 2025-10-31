package uploadrevision

import "net/http"

// Opt is a function that configures an HTTPSealableClient instance.
type Opt func(*HTTPSealableClient)

// WithHTTPClient sets a custom HTTP client for the file upload client.
func WithHTTPClient(httpClient *http.Client) Opt {
	return func(c *HTTPSealableClient) {
		c.httpClient = httpClient
	}
}
