package middleware

import (
	"log"
	"net/http"
	"net/url"

	"github.com/snyk/go-httpauth/pkg/httpauth"
)

func ConfigureProxy(
	transport *http.Transport,
	logger *log.Logger,
	proxy func(req *http.Request) (*url.URL, error),
	authenticationMechanism httpauth.AuthenticationMechanism,
) *http.Transport {
	transport = transport.Clone()

	// create proxy authenticator if required
	var proxyAuthenticator *httpauth.ProxyAuthenticator
	if httpauth.IsSupportedMechanism(authenticationMechanism) {
		proxyAuthenticator = httpauth.NewProxyAuthenticator(authenticationMechanism, proxy, logger)
		transport.DialContext = proxyAuthenticator.DialContext
		transport.Proxy = nil
	} else {
		transport.DialContext = nil
		transport.Proxy = proxy
	}
	return transport
}
