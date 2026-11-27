// Package proxy holds the proxy decision shared by the HTTP transport and the code that reports on it.
package proxy

import (
	"net/http"
	"net/url"
)

// FromEnvironment returns the proxy URL for req, or nil when req is sent directly.
func FromEnvironment(req *http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment(req)
}
